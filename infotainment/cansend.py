#!/usr/bin/env python3
"""
간단한 cansend - CAN 데몬과 파이프로 통신
"""
import sys
import json
import time
import os

def parse_can_message(msg_str):
    """CAN 메시지 파싱"""
    if '#' not in msg_str:
        raise ValueError("Invalid CAN message format")
    
    can_id_str, data_str = msg_str.split('#', 1)
    can_id = int(can_id_str, 16)
    
    if len(data_str) > 16:
        raise ValueError("CAN data too long")
    
    if len(data_str) % 2:
        data_str = '0' + data_str
        
    return can_id, data_str

def send_can_message(interface, message):
    """CAN 메시지 전송"""
    can_id, data = parse_can_message(message)
    
    # CAN 데몬 파이프로 메시지 전송
    pipe_path = "/tmp/can_daemon/send"
    
    # 파이프가 없으면 잠시 대기 (데몬 시작 중일 수 있음)
    for i in range(10):
        if os.path.exists(pipe_path):
            break
        time.sleep(0.5)
    else:
        print("Error: CAN daemon not running")
        sys.exit(1)
    
    msg_data = {
        'type': 'send',
        'can_id': can_id,
        'data': data,
        'timestamp': time.time()
    }
    
    try:
        # non-blocking write
        with open(pipe_path, 'w') as pipe:
            pipe.write(json.dumps(msg_data) + '\n')
            pipe.flush()
    except Exception as e:
        print(f"Error sending message: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) != 3:
        print("Usage: cansend <interface> <can_id>#<data>")
        sys.exit(1)
    
    interface = sys.argv[1]
    message = sys.argv[2]
    
    send_can_message(interface, message)

if __name__ == "__main__":
    main()