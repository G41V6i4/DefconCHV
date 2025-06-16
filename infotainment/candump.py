#!/usr/bin/env python3
"""
간단한 candump - CAN 데몬에서 메시지 수신
"""
import sys
import os
import signal
import time

def signal_handler(signum, frame):
    sys.exit(0)

def dump_messages(interface):
    """CAN 메시지 덤프"""
    log_file = "/tmp/can_daemon/messages.log"
    
    # 로그 파일이 없으면 잠시 대기
    for i in range(10):
        if os.path.exists(log_file):
            break
        time.sleep(0.5)
    else:
        print("Error: CAN daemon not running")
        sys.exit(1)
    
    # 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"Listening on {interface}...")
    
    try:
        with open(log_file, 'r') as f:
            # 기존 내용 먼저 출력
            lines = f.readlines()
            for line in lines:
                print(line.strip())
            
            # 파일 끝으로 이동해서 새 내용 감시
            f.seek(0, 2)  # 파일 끝으로 이동
            
            while True:
                line = f.readline()
                if line:
                    print(line.strip())
                else:
                    time.sleep(0.1)  # 새 데이터 대기
                    
    except Exception as e:
        print(f"Error reading messages: {e}")

def main():
    if len(sys.argv) < 2:
        print("Usage: candump <interface>")
        sys.exit(1)
    
    interface = sys.argv[1]
    dump_messages(interface)

if __name__ == "__main__":
    main()