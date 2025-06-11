#!/usr/bin/env python3
import socket
import threading
import struct
import subprocess
import os
import time
import binascii

# 서버 설정
HOST = '0.0.0.0'
PORT = 1337

# 전역 변수
diagnostic_mode = False
security_level = 0
can_interface_name = "vcan0"  # 호스트의 vcan0 인터페이스 사용

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

# CAN 메시지 모니터링 스레드
def can_monitor(sock):
    print("[+] CAN monitoring started")
    while True:
        can_id, data = receive_can_message(sock)
        if can_id:
            # 엔진 ECU(ID: 0x7E8)로부터의 응답 처리
            if can_id == 0x7E8:
                process_engine_response(data)
        time.sleep(0.01)  # 약간의 지연으로 CPU 사용량 감소

# 엔진 ECU 응답 처리
def process_engine_response(data):
    if len(data) < 1:
        return
    
    service_id = data[0]
    # UDS 응답 처리 (0x40 이상은 긍정 응답)
    if service_id >= 0x40:
        original_service = service_id - 0x40
        print(f"[+] Engine ECU response 0x{original_service:02X}, data: {data[1:].hex()}")
    # 부정 응답 처리 (0x7F)
    elif service_id == 0x7F:
        print(f"[!] Engine ECU error: service 0x{data[1]:02X}, code: 0x{data[2]:02X}")

# 명령어 처리
def process_command(cmd, can_socket):
    global diagnostic_mode, security_level
    
    if cmd.strip() == "help":
        return """Available commands:
help - Display help
status - Check system status
exit - Close connection
enable_diag_mode [password] - Enable diagnostic mode
diag_service [command] - Execute diagnostic service (diagnostic mode required)
can_send [ID] [DATA] - Send CAN message (diagnostic mode required)
"""
    
    elif cmd.strip() == "status":
        status = "Normal" if diagnostic_mode else "Limited"
        return f"System status: {status}\nSecurity level: {security_level}"
    
    elif cmd.startswith("enable_diag_mode"):
        parts = cmd.split()
        if len(parts) > 1 and parts[1] == "hacker123":
            diagnostic_mode = True
            return "Diagnostic mode activated successfully!\nYou can now use diag_service and can_send commands."
        return "Invalid password."
    
    elif cmd.startswith("diag_service"):
        if not diagnostic_mode:
            return "Error: Diagnostic mode is not activated."
        
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return "Usage: diag_service [command]"
        
        return diagnostic_service(parts[1])
    
    elif cmd.startswith("can_send"):
        if not diagnostic_mode:
            return "Error: Diagnostic mode is not activated."
        
        if not can_socket:
            return "Error: CAN interface not available."
        
        parts = cmd.split()
        if len(parts) < 3:
            return "Usage: can_send [ID] [DATA]"
        
        try:
            can_id = int(parts[1], 16)
            data = binascii.unhexlify(parts[2])
            if len(data) > 8:
                return "Error: Data must be at most 8 bytes."
            
            if send_can_message(can_socket, can_id, data):
                return f"CAN message sent successfully: ID=0x{can_id:X}, Data={data.hex()}"
            else:
                return "CAN message transmission failed."
        except ValueError:
            return "Error: ID must be hexadecimal, data must be a hexadecimal string."
    
    else:
        return "Unknown command. Type 'help' to see available commands."

# 취약한 진단 서비스 처리 - 버퍼 오버플로우 취약점
def diagnostic_service(param):
    global security_level
    
    # 취약한 버퍼 할당 (고정 크기)
    buffer = bytearray(20)
    
    try:
        # 의도적인 버퍼 오버플로우 취약점
        # 버퍼보다 큰 입력을 받아도 제한 없이 복사 시도
        for i in range(len(param)):
            if i < len(buffer):
                buffer[i] = ord(param[i]) if isinstance(param[i], str) else param[i]
            else:
                # 버퍼 오버플로우 발생!
                if param[i:i+8] == "OVERFLOW":
                    security_level = 2  # 보안 레벨 상승 (시뮬레이션)
                    # 침투 성공 시 쉘 액세스 제공 (CTF 목적)
                    return "### Buffer overflow detected! ###\nSecurity level increased to 2.\n\nShell access granted: Use the 'shell' command."
    except Exception as e:
        return f"Error occurred: {e}"
    
    # 일반 응답
    return f"Diagnostic service executed: {param}\nResult: Processing complete"

# 클라이언트 처리
import os
import pty
import select
import subprocess
import fcntl

def handle_client(conn, addr, can_socket):  # security_level 파라미터 추가
    global security_level
    print(f"[+] New connection: {addr}")
    conn.send(b"Connected to Infotainment ECU System.\n> ")
    
    shell_mode = False
    
    while True:
        try:
            data = conn.recv(1024).decode('utf-8').strip()
            if not data:
                break
            
            # 일반 명령어 처리
            if data.lower() == "exit":
                break
            
            # 쉘 모드 진입
            if data.lower() == "shell" and security_level >= 2:
                shell_mode = True
                conn.send(b"\n### Shell access granted ###\n$ ")
                
                # 대화형 쉘 구현
                # pty 생성
                master, slave = pty.openpty()
                
                # 실제 bash 프로세스 실행
                shell_process = subprocess.Popen(
                    ["/bin/bash"], 
                    stdin=slave,
                    stdout=slave, 
                    stderr=slave,
                    preexec_fn=os.setsid  # 새 세션 생성
                )
                
                # 슬레이브는 더 이상 필요 없음
                os.close(slave)
                
                # 비차단 모드로 설정
                old_flags = fcntl.fcntl(master, fcntl.F_GETFL)
                fcntl.fcntl(master, fcntl.F_SETFL, old_flags | os.O_NONBLOCK)
                
                # 클라이언트에서 소켓도 비차단 모드로 설정
                conn.setblocking(False)
                
                try:
                    # 쉘 모드 루프
                    while shell_mode:
                        ready, _, _ = select.select([conn, master], [], [], 0.1)
                        
                        # 클라이언트에서 입력이 있는 경우
                        if conn in ready:
                            try:
                                client_data = conn.recv(1024)
                                if not client_data:  # 연결 종료
                                    shell_mode = False
                                    break
                                
                                # 'exit' 명령어 확인 (쉘 종료)
                                if client_data.strip().lower() == b'exit':
                                    shell_mode = False
                                    break
                                
                                # 입력을 쉘로 전달
                                os.write(master, client_data)
                            except BlockingIOError:
                                pass
                        
                        # 쉘에서 출력이 있는 경우
                        if master in ready:
                            try:
                                shell_output = os.read(master, 1024)
                                if shell_output:
                                    conn.send(shell_output)  # 출력을 클라이언트로 전송
                            except (OSError, BlockingIOError):
                                pass
                
                finally:
                    # 정리: 쉘 프로세스 종료
                    try:
                        os.killpg(os.getpgid(shell_process.pid), 9)  # SIGKILL
                    except:
                        pass
                    os.close(master)
                    
                    # 소켓을 다시 차단 모드로 설정
                    conn.setblocking(True)
                    
                    # 쉘 종료 메시지 전송
                    conn.send(b"\nShell session ended.\nReturned to Infotainment ECU System.\n> ")
                    
                    # 원래 모드로 돌아감
                    shell_mode = False
                
                continue
            
            # 일반 명령어 처리
            response = process_command(data, can_socket)
            conn.send(response.encode('utf-8') + b"\n> ")
            
        except Exception as e:
            print(f"[!] Error: {e}")
            conn.send(f"An error occurred: {e}\n> ".encode('utf-8'))
    
    print(f"[-] Connection closed: {addr}")
    conn.close()
# 메인 함수
if __name__ == "__main__":
    # CAN 소켓 초기화
    can_socket = init_can_socket()
    if can_socket:
        # CAN 모니터링 스레드 시작
        monitor_thread = threading.Thread(target=can_monitor, args=(can_socket,), daemon=True)
        monitor_thread.start()
    else:
        print("[!] CAN functionality will be limited")
    
    # 서버 소켓 설정
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(5)
    
    print(f"[+] Server started at {HOST}:{PORT}")
    
    try:
        while True:
            conn, addr = server.accept()
            client_thread = threading.Thread(target=handle_client, args=(conn, addr, can_socket), daemon=True)
            client_thread.start()
    except KeyboardInterrupt:
        print("\n[!] Server shutdown")
    finally:
        server.close()
        if can_socket:
            can_socket.close()