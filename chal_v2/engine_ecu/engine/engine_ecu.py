#!/usr/bin/env python3
import socket
import struct
import binascii
import time
import threading
import os

# 설정
can_interface_name = "vcan1" # 호스트의 vcan0 인터페이스 사용
ENGINE_ECU_ID = 0x7E0  # 엔진 ECU의 송신 ID
ENGINE_RESPONSE_ID = 0x7E8  # 엔진 ECU의 응답 ID

# 보안 관련 변수
security_access_seed = b"\xDE\xAD\xBE\xEF"  # 고정 시드 값 (데모용)
security_unlocked = False

# 플래그 (CTF 목적)
FLAG = "CHV{3CU_h4ck1ng_c0mpl3t3d_c0ngratul4t10ns!}"

# CAN 소켓 초기화
def init_can_socket():
    try:
        # CAN 소켓 생성 및 연결
        can_socket = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        can_socket.bind((can_interface_name,))
        print(f"[+] Connected to CAN interface {can_interface_name}")
        return can_socket
    except Exception as e:
        print(f"[!] CAN socket initialization failed: {e}")
        # 호스트의 인터페이스에 연결하지 못하면 시뮬레이션 모드로 전환
        print("[!] Please make sure vcan0 is created on the host with 'sudo ip link add dev vcan0 type vcan'")
        return None

# CAN 메시지 송신
def send_can_message(sock, can_id, data):
    if not sock:
        print("[!] CAN socket not initialized")
        return False
        
    try:
        # CAN 프레임 형식: ID(4바이트) + 길이(1바이트) + 패딩(3바이트) + 데이터(최대 8바이트)
        data = data.ljust(8, b'\x00')  # 8바이트로 패딩
        can_frame = struct.pack("=IB3x8s", can_id, len(data), data)
        sock.send(can_frame)
        print(f"[>] CAN TX: ID=0x{can_id:X}, Data={data[:len(data)].hex()}")
        return True
    except Exception as e:
        print(f"[!] CAN message send failed: {e}")
        return False

# CAN 메시지 수신
def receive_can_message(sock, timeout=1.0):
    if not sock:
        return None, None
        
    sock.settimeout(timeout)
    try:
        frame = sock.recv(16)
        can_id, length, data = struct.unpack("=IB3x8s", frame)
        print(f"[<] CAN RX: ID=0x{can_id:X}, Data={data[:length].hex()}")
        return can_id, data[:length]
    except socket.timeout:
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

# CAN 메시지 리스너
def can_listen(sock):
    print("[+] Engine ECU started - listening for CAN messages")
    
    while True:
        try:
            can_id, data = receive_can_message(sock)
            
            if can_id == ENGINE_ECU_ID:  # 엔진 ECU로 향하는 메시지
                print(f"[+] Received request for Engine ECU: {data.hex()}")
                response = process_uds_request(can_id, data)
                
                if response:
                    # 응답 전송
                    send_can_message(sock, ENGINE_RESPONSE_ID, response)
        
        except Exception as e:
            print(f"[!] Error in CAN listener: {e}")
            time.sleep(1)  # 오류 발생 시 잠시 대기

# 메인 함수
if __name__ == "__main__":
    # CAN 소켓 초기화 (시도)
    for i in range(5):  # 여러 번 연결 시도
        print(f"[*] Attempting to connect to CAN interface (attempt {i+1}/5)")
        can_socket = init_can_socket()
        if can_socket:
            break
        time.sleep(2)  # 재시도 전 대기
    
    if not can_socket:
        print("[!] Failed to initialize CAN socket after multiple attempts.")
        print("[!] Make sure vcan0 is properly set up on the host.")
        print("[!] Try manually with: sudo modprobe vcan && sudo ip link add dev vcan0 type vcan && sudo ip link set up vcan0")
        exit(1)
    
    try:
        # CAN 메시지 리스닝 시작
        can_listen(can_socket)
    except KeyboardInterrupt:
        print("\n[!] Engine ECU shutdown")
    finally:
        if can_socket:
            can_socket.close()