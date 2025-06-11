#!/usr/bin/env python3
"""
이 스크립트는 CTF 문제용 가짜 펌웨어 파일을 생성합니다.
펌웨어 내에 디버그 명령어와 플래그를 숨깁니다.
"""
import random
import struct
import os

def create_firmware_bin():
    # 랜덤 데이터로 시작하는 펌웨어 파일
    firmware_data = bytearray(random.getrandbits(8) for _ in range(4096))
    
    # 펌웨어 헤더 (가짜)
    header = b"INFOTAINMENT_ECU_v2.1"
    for i in range(len(header)):
        firmware_data[i] = header[i]
    
    # 숨겨진 디버그 명령어 (1단계 플래그)
    debug_cmd = b"DEBUG_CMD: enable_diag_mode hacker123\x00"
    offset1 = 0x500  # 임의의 오프셋
    for i in range(len(debug_cmd)):
        firmware_data[offset1 + i] = debug_cmd[i]
    
    # 힌트: 버퍼 오버플로우 공격 문자열 (2단계 힌트)
    overflow_hint = b"Hint: buffer[20] might overflow with 'OVERFLOW' pattern\x00"
    offset2 = 0x800  # 임의의 오프셋
    for i in range(len(overflow_hint)):
        firmware_data[offset2 + i] = overflow_hint[i]
    
    # CAN 통신 관련 힌트 (3단계 힌트)
    can_hint = b"Engine ECU ID: 0x7E0, UDS Request format: [service_id][sub_function][data...]\x00"
    offset3 = 0xA00  # 임의의 오프셋
    for i in range(len(can_hint)):
        firmware_data[offset3 + i] = can_hint[i]
    
    # 파일 저장
    with open("firmware.bin", "wb") as f:
        f.write(firmware_data)
    
    print(f"펌웨어 파일 생성 완료: firmware.bin ({len(firmware_data)} 바이트)")

if __name__ == "__main__":
    create_firmware_bin()
