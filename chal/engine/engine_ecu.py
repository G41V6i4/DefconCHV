#!/usr/bin/env python3
import socket
import struct
import binascii
import time
import threading
import os

# 설정
CAN_BRIDGE_HOST = "can_bridge"  # can_bridge 컨테이너 이름
CAN_BRIDGE_PORT = 12345         # can_bridge 포트
ENGINE_ECU_ID = 0x7E0           # 엔진 ECU의 송신 ID
ENGINE_RESPONSE_ID = 0x7E8      # 엔진 ECU의 응답 ID

# 보안 관련 변수
security_access_seed = b"\xDE\xAD\xBE\xEF"  # 고정 시드 값 (데모용)
security_unlocked = False

# 플래그 (CTF 목적)
FLAG = "CHV{3CU_h4ck1ng_c0mpl3t3d_c0ngratul4t10ns!}"

# TCP 소켓으로 CAN 브릿지에 연결
def connect_to_can_bridge():
    for retry in range(5):  # 5번 재시도
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # TCP Keep-Alive 설정
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # Linux 커널 매개변수 (필요한 경우)
            try:
                if hasattr(socket, 'TCP_KEEPIDLE'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)  # 60초 후 KEEPALIVE 시작
                if hasattr(socket, 'TCP_KEEPINTVL'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)  # 10초 간격으로 재시도
                if hasattr(socket, 'TCP_KEEPCNT'):
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 6)  # 6회 실패 시 연결 종료
            except Exception as e:
                print(f"[!] Warning: Could not set TCP Keep-Alive options: {e}")
            
            # 소켓 버퍼 크기 설정
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8192)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 8192)
            
            # 차단 모드로 설정
            sock.setblocking(True)
            
            # 작은 delay 추가로 연결 안정성 향상
            time.sleep(0.1)
            
            sock.connect((CAN_BRIDGE_HOST, CAN_BRIDGE_PORT))
            print(f"[+] Connected to CAN bridge at {CAN_BRIDGE_HOST}:{CAN_BRIDGE_PORT}")
            
            # 연결 성공 후 잠시 대기
            time.sleep(0.5)
            
            return sock
        except Exception as e:
            print(f"[!] Failed to connect to CAN bridge (attempt {retry+1}/5): {e}")
            try:
                sock.close()
            except:
                pass
            time.sleep(2)  # 재시도 전 대기
    
    print("[!] Could not connect to CAN bridge after multiple attempts")
    return None

# CAN 메시지 송신 (TCP를 통해)
def send_can_message(sock, can_id, data):
    if not sock:
        print("[!] Not connected to CAN bridge")
        return False
        
    try:
        # CAN 프레임 형식: ID(4바이트) + 길이(1바이트) + 패딩(3바이트) + 데이터(최대 8바이트)
        data_len = len(data)
        data = data.ljust(8, b'\x00')  # 8바이트로 패딩
        can_frame = struct.pack("=IB3x8s", can_id, data_len, data)
        
        # 디버그: 전송 데이터 출력
        print(f"[DEBUG] Sending: ID=0x{can_id:X}, Len={data_len}, Data={data[:data_len].hex()}")
        
        # 전송
        bytes_sent = sock.sendall(can_frame)
        print(f"[>] CAN TX: ID=0x{can_id:X}, Data={data[:data_len].hex()}")
        
        # 전송 후 잠시 대기하여 네트워크 버퍼가 비워지도록 함
        time.sleep(0.01)
        
        return True
    except Exception as e:
        print(f"[!] CAN message send failed: {e}")
        return False

# CAN 메시지 수신 (TCP를 통해)
def receive_can_message(sock, timeout=30.0):  # 시간 초과 값을 30초로 설정
    if not sock:
        return None, None
        
    try:
        sock.settimeout(timeout)
        
        # 첫 4바이트 (CAN ID) 읽기 시도
        header = sock.recv(4)
        if not header or len(header) < 4:
            if len(header) == 0:
                print("[DEBUG] Connection closed by peer (empty header)")
            else:
                print(f"[DEBUG] Incomplete header received: {len(header)} bytes")
            return None, None
            
        # 나머지 12바이트 (길이 + 패딩 + 데이터) 읽기 시도
        remaining = sock.recv(12)
        if not remaining or len(remaining) < 12:
            print(f"[DEBUG] Incomplete frame data: {len(remaining)} bytes")
            return None, None
            
        # 전체 프레임 재구성
        frame = header + remaining
        
        # 프레임 파싱
        can_id, length, data = struct.unpack("=IB3x8s", frame)
        
        # 길이 유효성 검사
        if length > 8:
            print(f"[DEBUG] Invalid length in frame: {length}")
            return None, None
            
        print(f"[<] CAN RX: ID=0x{can_id:X}, Data={data[:length].hex()}")
        return can_id, data[:length]
        
    except socket.timeout:
        # 정상적인 시간 초과는 조용히 처리
        return None, None
    except ConnectionResetError:
        print("[!] Connection reset by peer")
        return None, None
    except Exception as e:
        print(f"[!] CAN message receive failed: {e}")
        return None, None

# UDS 진단 서비스 처리
def process_uds_request(can_id, data):
    global security_unlocked
    
    if not data:
        return None
    
    service_id = data[0]
    
    # 시작 진단 세션 (0x10)
    if service_id == 0x10:
        session_type = data[1] if len(data) > 1 else 0
        print(f"[+] Diagnostic session control: {session_type}")
        return bytes([0x50, session_type, 0x00])  # 긍정 응답
    
    # ECU 재설정 (0x11)
    elif service_id == 0x11:
        reset_type = data[1] if len(data) > 1 else 0
        print(f"[+] ECU reset: {reset_type}")
        return bytes([0x51, reset_type])  # 긍정 응답
    
    # 보안 접근 - 시드 요청 (0x27, 0x01)
    elif service_id == 0x27 and len(data) > 1 and data[1] == 0x01:
        print("[+] Security access - seed request")
        return bytes([0x67, 0x01]) + security_access_seed  # 시드 반환
    
    # 보안 접근 - 키 전송 (0x27, 0x02)
    elif service_id == 0x27 and len(data) > 1 and data[1] == 0x02:
        key = data[2:6] if len(data) > 5 else b""
        print(f"[+] Security access - key: {key.hex()}")
        
        # 간단한 XOR 알고리즘 (시드를 0xFF와 XOR)
        expected_key = bytes([b ^ 0xFF for b in security_access_seed])
        
        if key == expected_key:
            security_unlocked = True
            print("[+] Security access granted")
            return bytes([0x67, 0x02])  # 긍정 응답
        else:
            print("[!] Invalid security key")
            return bytes([0x7F, 0x27, 0x35])  # 부정 응답 (잘못된 키)
    
    # 데이터 읽기 (0x22)
    elif service_id == 0x22:
        if len(data) < 3:
            return bytes([0x7F, 0x22, 0x12])  # 부정 응답 (하위 함수 없음)
        
        data_id = (data[1] << 8) | data[2]  # 2바이트 데이터 ID
        print(f"[+] Read data by identifier: 0x{data_id:04X}")
        
        # 플래그 데이터 ID (0xF154, CTF 목적)
        if data_id == 0xF154:
            if security_unlocked:
                flag_bytes = FLAG.encode('utf-8')
                return bytes([0x62, 0xF1, 0x54]) + flag_bytes  # 플래그 반환
            else:
                return bytes([0x7F, 0x22, 0x33])  # 보안 액세스 거부
        
        # 기타 데이터 ID는 부정 응답
        return bytes([0x7F, 0x22, 0x31])  # 부정 응답 (요청 범위 초과)
    
    # 알 수 없는 서비스
    else:
        return bytes([0x7F, service_id, 0x11])  # 부정 응답 (서비스 지원 안 함)

# 하트비트 스레드 - 연결 유지를 위해 주기적으로 메시지 전송
def heartbeat_thread(sock):
    """연결 유지를 위해 주기적으로 더미 메시지를 전송"""
    while True:
        time.sleep(10)  # 10초마다 실행
        try:
            if sock is None:
                continue
                
            # 더미 메시지 (CAN ID 0x100, 데이터 0x00)
            dummy_frame = struct.pack("=IB3x8s", 0x100, 1, b'\x00\x00\x00\x00\x00\x00\x00\x00')
            sock.sendall(dummy_frame)
            print("[DEBUG] Sent heartbeat message")
        except:
            # 오류 무시 (메인 스레드에서 처리)
            pass

# CAN 메시지 리스너 (TCP 버전)
# CAN 메시지 리스너 (TCP 버전)
def can_listen(sock):
    print("[+] Engine ECU started - listening for CAN messages via bridge")
    
    # 하트비트 스레드 시작
    heartbeat_t = threading.Thread(target=heartbeat_thread, args=(sock,), daemon=True)
    heartbeat_t.start()
    
    connection_attempts = 0
    max_connection_attempts = 5  # 최대 연속 재연결 시도 횟수
    
    while True:
        try:
            if sock is None:
                print("[!] Socket is None, attempting to reconnect...")
                sock = connect_to_can_bridge()
                if not sock:
                    connection_attempts += 1
                    if connection_attempts >= max_connection_attempts:
                        print(f"[!] Failed to reconnect after {max_connection_attempts} attempts. Waiting longer...")
                        time.sleep(30)  # 더 오래 대기
                        connection_attempts = 0
                    else:
                        time.sleep(5)  # 5초 대기
                else:
                    connection_attempts = 0  # 연결 성공시 카운터 리셋
                continue
                
            can_id, data = receive_can_message(sock)
            
            # 타임아웃이면 계속 진행
            if can_id is None and data is None:
                continue
                
            # 연결 끊김 감지
            if can_id is None:
                print("[!] Connection to CAN bridge lost, attempting to reconnect...")
                try:
                    sock.close()
                except:
                    pass
                sock = None  # 다음 루프에서 재연결
                continue
            
            # 확장 ID(0x80000000) 및 세션 해시(0x0000XXXX) 제거하여 기본 ID 추출
            base_id = can_id & 0x7FF  # 11비트 CAN ID 마스크
            
            # 로그에 보여주기 위한 추가 정보
            is_extended = bool(can_id & 0x80000000)
            session_hash = (can_id >> 11) & 0xFFFF if is_extended else 0
            
            print(f"[DEBUG] Full CAN ID: 0x{can_id:X}, Base ID: 0x{base_id:X}, "
                  f"Extended: {is_extended}, Session Hash: 0x{session_hash:X}")
            
            # 이제 기본 ID를 사용하여 비교
            if base_id == ENGINE_ECU_ID:  # 엔진 ECU로 향하는 메시지
                print(f"[+] Received request for Engine ECU: {data.hex()}")
                response = process_uds_request(can_id, data)
                
                if response:
                    # 응답 ID도 변경 필요
                    response_id = ENGINE_RESPONSE_ID
                    
                    # 확장 ID 사용 중이면 응답도 동일한 형식 유지
                    if is_extended:
                        response_id = 0x80000000 | (session_hash << 11) | ENGINE_RESPONSE_ID
                    
                    # 응답 전송
                    if not send_can_message(sock, response_id, response):
                        print("[!] Failed to send response, reconnecting...")
                        try:
                            sock.close()
                        except:
                            pass
                        sock = None  # 다음 루프에서 재연결
        
        except Exception as e:
            print(f"[!] Error in CAN listener: {e}")
            # 연결 오류일 가능성이 높으므로 재연결 시도
            try:
                sock.close()
            except:
                pass
            sock = None  # 다음 루프에서 재연결
            time.sleep(1)  # 오류 발생 시 잠시 대기
# 메인 함수
if __name__ == "__main__":
    print("[*] Starting Engine ECU with TCP-based CAN communication")
    
    # 시작 전 잠시 대기 (다른 서비스가 먼저 시작되도록)
    time.sleep(3)
    
    # CAN 브릿지에 연결
    bridge_socket = connect_to_can_bridge()
    
    # 최초 연결 실패해도 계속 진행 (can_listen 내에서 재연결 시도)
    if not bridge_socket:
        print("[!] Initial connection to CAN bridge failed. Will retry in the main loop.")
    
    try:
        # CAN 메시지 리스닝 시작
        can_listen(bridge_socket)
    except KeyboardInterrupt:
        print("\n[!] Engine ECU shutdown")
    finally:
        if bridge_socket:
            try:
                bridge_socket.close()
            except:
                pass