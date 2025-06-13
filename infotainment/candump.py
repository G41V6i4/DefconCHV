#!/usr/bin/env python3
"""
Custom candump command - can-utils 호환
Usage: candump vcan0
"""
import sys
import socket
import json
import os
import time
import signal
import threading

class CANDump:
    def __init__(self, interface):
        self.interface = interface
        self.running = False
        self.sock = None
        
    def get_session_id(self):
        """컨테이너 이름에서 세션 ID 추출"""
        hostname = os.environ.get('HOSTNAME', socket.gethostname())
        
        if hostname.startswith('infotainment_'):
            return hostname[13:]  # 'infotainment_' 제거
        elif hostname.startswith('engine_'):
            return 'engine_shared'
        else:
            return hostname
    
    def connect_to_broker(self):
        """CAN 브로커에 연결"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(('gateway_shared', 9999))
            
            # 핸드셰이크
            session_id = self.get_session_id()
            client_type = 'engine' if session_id == 'engine_shared' else 'infotainment'
            
            handshake = {
                'session_id': session_id,
                'type': client_type
            }
            
            self.sock.send(json.dumps(handshake).encode())
            
            # 핸드셰이크 응답 대기
            response = self.sock.recv(1024).decode().strip()
            resp_data = json.loads(response)
            
            if resp_data['status'] != 'connected':
                raise Exception("Handshake failed")
                
            return session_id
            
        except Exception as e:
            print(f"Error connecting to CAN broker: {e}")
            sys.exit(1)
    
    def format_can_message(self, can_id, data, timestamp):
        """CAN 메시지를 can-utils 형식으로 포맷"""
        # 형식: (timestamp) vcan0 123#DEADBEEF
        time_str = f"({timestamp:.6f})"
        can_id_str = f"{can_id:03X}"
        data_str = data.upper() if data else ""
        
        return f"{time_str} {self.interface} {can_id_str}#{data_str}"
    
    def dump_messages(self):
        """CAN 메시지 덤프 시작"""
        session_id = self.connect_to_broker()
        self.running = True
        
        # candump 시작 신호 전송
        start_msg = {
            'type': 'dump_start',
            'timestamp': time.time()
        }
        self.sock.send((json.dumps(start_msg) + '\n').encode())
        
        # 메시지 수신 루프
        buffer = ""
        try:
            while self.running:
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        self.process_received_message(line.strip())
                        
        except KeyboardInterrupt:
            self.stop()
        except Exception as e:
            if self.running:
                print(f"Error receiving messages: {e}")
        finally:
            self.cleanup()
    
    def process_received_message(self, message):
        """수신된 메시지 처리"""
        try:
            msg_data = json.loads(message)
            
            if msg_data['type'] == 'receive':
                # CAN 메시지 수신
                formatted = self.format_can_message(
                    msg_data['can_id'],
                    msg_data['data'],
                    msg_data['timestamp']
                )
                print(formatted)
                
        except Exception as e:
            # JSON 파싱 오류는 조용히 무시 (can-utils 호환)
            pass
    
    def stop(self):
        """덤프 중지"""
        self.running = False
    
    def cleanup(self):
        """리소스 정리"""
        if self.sock:
            self.sock.close()

def signal_handler(signum, frame):
    """시그널 핸들러"""
    global dumper
    if dumper:
        dumper.stop()
    sys.exit(0)

def main():
    global dumper
    
    if len(sys.argv) < 2:
        print("Usage: candump <interface> [options]")
        print("Example: candump vcan0")
        sys.exit(1)
    
    interface = sys.argv[1]
    
    # 옵션 파싱 (기본적인 것들만)
    if '-h' in sys.argv or '--help' in sys.argv:
        print("candump - CAN message dump utility")
        print("Usage: candump <interface>")
        print("  interface: CAN interface name (e.g. vcan0)")
        sys.exit(0)
    
    # 인터페이스 이름 검증
    valid_interfaces = ['vcan0', 'vcan1', 'can0', 'can1']
    if interface not in valid_interfaces:
        print(f"Warning: Unknown interface '{interface}', using anyway...")
    
    # 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # CAN 덤프 시작
    dumper = CANDump(interface)
    dumper.dump_messages()

if __name__ == "__main__":
    dumper = None
    main()