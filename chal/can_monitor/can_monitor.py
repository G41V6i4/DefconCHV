#!/usr/bin/env python3
# 파일명: ./can_monitor/can_monitor.py

import socket
import struct
import sys
import time
import argparse

def main():
    parser = argparse.ArgumentParser(description='CAN TCP Monitor')
    parser.add_argument('host', nargs='?', default='can_bridge', help='CAN Bridge hostname')
    parser.add_argument('port', nargs='?', type=int, default=12345, help='CAN Bridge port')
    args = parser.parse_args()

    print(f"[*] Connecting to CAN Bridge at {args.host}:{args.port}")
    
    try:
        # TCP 소켓 생성 및 연결
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((args.host, args.port))
        print(f"[+] Connected to {args.host}:{args.port}")
        
        # candump 스타일로 출력
        print("┌─────────────┬────────────┬───────────────────────────────────┐")
        print("│  Timestamp  │    ID      │   Data                            │")
        print("├─────────────┼────────────┼───────────────────────────────────┤")
        
        while True:
            # CAN 프레임 수신
            frame_data = sock.recv(16)  # struct can_frame 크기
            if not frame_data:
                break
                
            if len(frame_data) == 16:  # struct can_frame 크기
                # CAN 프레임 구조 해석
                can_id, length, data = struct.unpack("=IB3x8s", frame_data)
                
                # 시간 정보 추가
                timestamp = time.strftime("%H:%M:%S.%f")[:-3]
                
                # can_id가 확장 ID인지 확인
                is_extended = bool(can_id & 0x80000000)
                if is_extended:
                    id_display = f"{can_id & 0x1FFFFFFF:08X}"
                else:
                    id_display = f"{can_id & 0x7FF:03X}"
                
                # 데이터 출력
                data_str = " ".join([f"{b:02X}" for b in data[:length]])
                
                # candump 스타일 출력
                print(f"│ {timestamp} │ {id_display.ljust(10)} │ {data_str.ljust(35)} │")
    
    except KeyboardInterrupt:
        print("\n[*] Monitoring stopped by user")
    except Exception as e:
        print(f"[!] Error: {e}")
    finally:
        try:
            sock.close()
        except:
            pass
        print("└─────────────┴────────────┴───────────────────────────────────┘")
        print("[*] Connection closed")

if __name__ == "__main__":
    main()
