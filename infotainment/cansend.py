#!/usr/bin/env python3
"""
Custom cansend command - can-utils 호환
Usage: cansend vcan0 123#DEADBEEF
"""
import sys
import socket
import json
import os
import time

def parse_can_message(msg_str):
    try:
        # 형식: 123#DEADBEEF 또는 123#1234567890ABCDEF
        if '#' not in msg_str:
            raise ValueError("Invalid CAN message format")
        
        can_id_str, data_str = msg_str.split('#', 1)
        can_id = int(can_id_str, 16)
        
        # 데이터 길이 검증 (최대 8바이트)
        if len(data_str) > 16:  # 8바이트 = 16 hex chars
            raise ValueError("CAN data too long (max 8 bytes)")
        
        # 홀수 길이면 앞에 0 추가
        if len(data_str) % 2:
            data_str = '0' + data_str
            
        return can_id, data_str
    except Exception as e:
        print(f"Error parsing CAN message: {e}")
        sys.exit(1)

def get_session_id():
    """컨테이너 이름에서 세션 ID 추출"""
    hostname = os.environ.get('HOSTNAME', socket.gethostname())
    
    # infotainment_session_xxx 형식에서 session_xxx 추출
    if hostname.startswith('infotainment_'):
        return hostname[13:]  # 'infotainment_' 제거
    elif hostname.startswith('engine_'):
        return 'engine_shared'
    else:
        return hostname

def connect_to_broker():
    """CAN 브로커에 연결"""
    try:
        # 게이트웨이 컨테이너의 브로커에 연결
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('gateway_shared', 9999))
        
        # 핸드셰이크
        session_id = get_session_id()
        client_type = 'engine' if session_id == 'engine_shared' else 'infotainment'
        
        handshake = {
            'session_id': session_id,
            'type': client_type
        }
        
        sock.send(json.dumps(handshake).encode())
        
        # 핸드셰이크 응답 대기
        response = sock.recv(1024).decode().strip()
        resp_data = json.loads(response)
        
        if resp_data['status'] != 'connected':
            raise Exception("Handshake failed")
        
        return sock, session_id
    except Exception as e:
        print(f"Error connecting to CAN broker: {e}")
        sys.exit(1)

def send_can_message(interface, message):
    """CAN 메시지 전송"""
    can_id, data = parse_can_message(message)
    
    # 브로커에 연결
    sock, session_id = connect_to_broker()
    
    try:
        # CAN 메시지 전송
        msg_data = {
            'type': 'send',
            'can_id': can_id,
            'data': data,
            'timestamp': time.time()
        }
        
        sock.send((json.dumps(msg_data) + '\n').encode())
        
        # 전송 완료 - can-utils처럼 조용히 종료
        
    except Exception as e:
        print(f"Error sending CAN message: {e}")
        sys.exit(1)
    finally:
        sock.close()

def main():
    if len(sys.argv) != 3:
        print("Usage: cansend <interface> <can_id>#<data>")
        print("Example: cansend vcan0 123#DEADBEEF")
        sys.exit(1)
    
    interface = sys.argv[1]
    message = sys.argv[2]
    
    # 인터페이스 이름 검증 (실제로는 사용하지 않지만 호환성을 위해)
    valid_interfaces = ['vcan0', 'vcan1', 'can0', 'can1']
    if interface not in valid_interfaces:
        print(f"Warning: Unknown interface '{interface}', using anyway...")
    
    send_can_message(interface, message)

if __name__ == "__main__":
    main()