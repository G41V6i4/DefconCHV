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
    pipe_path = "/tmp/can_daemon/recv"
    
    # 파이프가 없으면 잠시 대기
    for i in range(10):
        if os.path.exists(pipe_path):
            break
        time.sleep(0.5)
    else:
        print("Error: CAN daemon not running")
        sys.exit(1)
    
    # 시그널 핸들러 등록
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        # non-blocking read로 변경
        while True:
            try:
                with open(pipe_path, 'r') as pipe:
                    line = pipe.readline()
                    if line:
                        print(line.strip())
                    else:
                        time.sleep(0.01)  # CPU 사용량 줄이기
            except:
                time.sleep(0.1)
                
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