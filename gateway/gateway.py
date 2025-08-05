#!/usr/bin/env python3

import socket
import threading
import json
import time
import struct
import logging
import hashlib
from collections import defaultdict

class SessionPRNG:
    def __init__(self, session_id):
        self.session_id = session_id
        seed = int(hashlib.md5(session_id.encode()).hexdigest()[:8], 16)
        self.state = seed ^ 0x12345678
        self.counter = 0
        
    def next(self):
        self.counter += 1
        self.state = ((self.state * 1103515245 + 12345) & 0x7FFFFFFF)
        return self.state

class UDSSecurityManager:
    def __init__(self, session_id, logger):
        self.session_id = session_id
        self.logger = logger
        self.prng = SessionPRNG(session_id)
        
        self.security_levels = {
            0x01: {'name': 'Basic Diagnostic', 'unlocked': False, 'attempts': 0, 'last_attempt': 0},
            0x03: {'name': 'Advanced Functions', 'unlocked': False, 'attempts': 0, 'last_attempt': 0}
        }
        
        self.active_seeds = {}
        self.session_start_time = time.time()
        
    def generate_seed(self, level):
        current_time = int(time.time())
        
        if level == 0x01:
            base_seed = self.prng.next()
            time_factor = current_time & 0xFF
            seed = (base_seed ^ (time_factor << 16)) & 0xFFFFFFFF
            
        elif level == 0x03:
            base_seed = self.prng.next()
            session_time = int(time.time() - self.session_start_time)
            time_factor = (current_time ^ session_time) & 0xFFFF
            seed = (base_seed ^ (time_factor << 8) ^ 0xCAFEBABE) & 0xFFFFFFFF
            
        else:
            return None
            
        self.active_seeds[level] = {
            'seed': seed,
            'timestamp': current_time,
            'attempts': 0
        }
        
        self.logger.info(f"[{self.session_id}] Generated seed for level 0x{level:02X}: 0x{seed:08X}")
        return seed
    
    def verify_key(self, level, provided_key):
        if level not in self.active_seeds:
            self.logger.warning(f"[{self.session_id}] No active seed for level 0x{level:02X}")
            return False, "Invalid security access sequence"
            
        seed_info = self.active_seeds[level]
        seed = seed_info['seed']
        seed_timestamp = seed_info['timestamp']
        
        seed_info['attempts'] += 1
        self.security_levels[level]['attempts'] += 1
        
        current_time = int(time.time())
        
        if current_time - seed_timestamp > 10:
            del self.active_seeds[level]
            self.logger.warning(f"[{self.session_id}] Seed timeout for level 0x{level:02X}")
            return False, "Security access timeout"
            
        if seed_info['attempts'] > 3:
            del self.active_seeds[level]
            self.security_levels[level]['last_attempt'] = current_time
            self.logger.warning(f"[{self.session_id}] Too many attempts for level 0x{level:02X}")
            return False, "Security access denied - too many attempts"
            
        expected_key = self.calculate_key(level, seed, seed_timestamp)
        
        verification_start = time.perf_counter()
        
        key_match = (provided_key == expected_key)
        
        if not key_match:
            high_nibbles_match = (provided_key >> 16) == (expected_key >> 16)
            if high_nibbles_match:
                time.sleep(0.05)
        else:
            time.sleep(0.02)
            
        verification_time = time.perf_counter() - verification_start
        
        if key_match:
            self.security_levels[level]['unlocked'] = True
            del self.active_seeds[level]
            self.security_levels[level]['last_attempt'] = current_time
            self.logger.info(f"[{self.session_id}] Security level 0x{level:02X} unlocked (verification: {verification_time:.4f}s)")
            return True, "Security access granted"
        else:
            self.logger.warning(f"[{self.session_id}] Invalid key for level 0x{level:02X}: got 0x{provided_key:08X}, expected 0x{expected_key:08X} (verification: {verification_time:.4f}s)")
            return False, "Invalid key"
    
    def calculate_key(self, level, seed, timestamp):
        if level == 0x01:
            return ((seed ^ 0xA5A5A5A5) + (timestamp & 0xFF)) & 0xFFFFFFFF
            
        elif level == 0x03:
            step1 = seed ^ 0x5A5A5A5A
            step2 = ((step1 << 3) | (step1 >> 29)) & 0xFFFFFFFF
            step3 = step2 + ((timestamp & 0xFFFF) * 0x9E3779B9)
            return step3 & 0xFFFFFFFF
            
        return 0
    
    def is_level_accessible(self, level):
        current_time = int(time.time())
        level_info = self.security_levels.get(level)
        
        if not level_info:
            return False, "Unknown security level"
            
        if level_info['last_attempt'] > 0 and current_time - level_info['last_attempt'] < 30:
            remaining = 30 - (current_time - level_info['last_attempt'])
            return False, f"Security lockout active - {remaining}s remaining"
            
        if level == 0x03 and not self.security_levels[0x01]['unlocked']:
            return False, "Level 1 access required first"
            
        return True, "Access permitted"

class CANMessage:
    def __init__(self, can_id, data, timestamp=None):
        self.can_id = can_id
        if isinstance(data, bytes) and len(data) > 8:
            raise ValueError(f"CAN data too long: {len(data)} bytes (max 8)")
        self.data = data
        self.timestamp = timestamp or time.time()
    
    def to_dict(self):
        return {
            'can_id': self.can_id,
            'data': self.data.hex() if isinstance(self.data, bytes) else self.data,
            'timestamp': self.timestamp
        }

class CANBroker:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.sessions = {}
        self.message_queues = defaultdict(list)
        self.security_managers = {}
        self.running = False
        
        self.setup_logging()
        
    def setup_logging(self):
        log_format = '%(asctime)s [%(levelname)s] %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler('/tmp/can_broker.log')
            ]
        )
        self.logger = logging.getLogger('CANBroker')
        self.logger.info("Advanced CAN Broker with UDS Security initialized")
        
    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.logger.info(f"Advanced CAN Broker started on {self.host}:{self.port}")
            
            stats_thread = threading.Thread(target=self.stats_reporter, daemon=True)
            stats_thread.start()
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    self.logger.info(f"New connection from {addr}")
                    
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, addr),
                        daemon=True
                    )
                    thread.start()
                    
                except Exception as e:
                    if self.running:
                        self.logger.error(f"Error accepting connection: {e}")
                        
        except Exception as e:
            self.logger.error(f"Failed to start CAN Broker: {e}")
            raise
    
    def handle_client(self, client_socket, addr):
        session_id = None
        client_type = None
        
        try:
            client_socket.settimeout(3600)
            
            data = client_socket.recv(1024).decode()
            if not data:
                self.logger.warning(f"Empty handshake from {addr}")
                return
                
            handshake = json.loads(data)
            session_id = handshake['session_id']
            client_type = handshake['type']
            
            self.logger.info(f"Handshake: session={session_id}, type={client_type}, addr={addr}")
            
            if session_id in self.sessions:
                self.logger.warning(f"Replacing existing session {session_id}")
                old_socket = self.sessions[session_id]['socket']
                try:
                    old_socket.close()
                except:
                    pass
            
            self.sessions[session_id] = {
                'socket': client_socket,
                'type': client_type,
                'addr': addr,
                'connected_at': time.time(),
                'last_activity': time.time(),
                'message_count': 0
            }
            
            if session_id not in self.security_managers:
                self.security_managers[session_id] = UDSSecurityManager(session_id, self.logger)
            
            response = {'status': 'connected', 'session_id': session_id}
            client_socket.send(json.dumps(response).encode() + b'\n')
            
            self.logger.info(f"Session {session_id} ({client_type}) connected from {addr}")
            
            buffer = ""
            while self.running:
                try:
                    data = client_socket.recv(1024).decode()
                    if not data:
                        self.logger.info(f"Client {session_id} disconnected")
                        break
                    
                    self.sessions[session_id]['last_activity'] = time.time()
                    buffer += data
                    
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip():
                            self.sessions[session_id]['message_count'] += 1
                            self.process_message(session_id, line.strip())
                            
                except socket.timeout:
                    self.logger.warning(f"1-hour timeout for session {session_id}")
                    break
                except Exception as e:
                    self.logger.error(f"Error receiving from {session_id}: {e}")
                    break
                        
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid handshake JSON from {addr}: {e}")
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
        finally:
            if session_id:
                if session_id in self.sessions:
                    del self.sessions[session_id]
                if session_id in self.security_managers:
                    del self.security_managers[session_id]
            client_socket.close()
    
    def process_message(self, session_id, message):
        try:
            msg_data = json.loads(message)
            msg_type = msg_data.get('type', 'unknown')
            
            if msg_type == 'send':
                can_data = bytes.fromhex(msg_data['data'])
                
                if len(can_data) > 8:
                    self.logger.error(f"[{session_id}] CAN data too long: {len(can_data)} bytes")
                    return
                
                can_msg = CANMessage(
                    can_id=msg_data['can_id'],
                    data=can_data
                )
                
                self.logger.info(f"CAN from {session_id}: ID=0x{can_msg.can_id:03X}, Data={can_msg.data.hex()} ({len(can_msg.data)} bytes)")
                self.route_message(session_id, can_msg)
                
            elif msg_type == 'dump_start':
                self.logger.info(f"Starting candump for {session_id}")
                self.send_queued_messages(session_id)
                
            elif msg_type == 'engine_response':
                # Engine ECU로부터의 응답 처리
                self.handle_engine_response(session_id, message)
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON from {session_id}: {e}")
        except Exception as e:
            self.logger.error(f"Error processing message from {session_id}: {e}")
    
    def route_message(self, sender_session, can_msg):
        sender_info = self.sessions.get(sender_session)
        if not sender_info:
            return
        
        sender_type = sender_info['type']
        
        if sender_type == 'infotainment':
            if can_msg.can_id == 0x7DF and len(can_msg.data) >= 3:
                self.handle_uds_request(sender_session, can_msg)
            elif can_msg.can_id == 0x456:
                self.handle_engine_access(sender_session, can_msg)
        
        elif sender_type == 'engine':
            self.handle_engine_response(sender_session, can_msg)
    
    def handle_uds_request(self, session_id, can_msg):
        data = can_msg.data
        if len(data) < 2:
            return
        
        # ISO-TP 프레이밍 파싱
        first_byte = data[0]
        
        if (first_byte & 0xF0) == 0x00:
            # Single Frame (0x0N)
            sf_length = first_byte & 0x0F
            if len(data) < sf_length + 1:
                self.logger.warning(f"[{session_id}] Invalid single frame length")
                return
            service_id = data[1]
            uds_data = data[1:sf_length+1]
            
        elif (first_byte & 0xF0) == 0x10:
            # First Frame (0x1N)
            total_length = ((first_byte & 0x0F) << 8) | data[1]
            if len(data) < 3:
                self.logger.warning(f"[{session_id}] Invalid first frame")
                return
            service_id = data[2]
            uds_data = data[2:]  # 첫 번째 프레임의 데이터
            
        else:
            self.logger.warning(f"[{session_id}] Unsupported frame type: 0x{first_byte:02X}")
            return
        
        self.logger.info(f"[{session_id}] UDS Service: 0x{service_id:02X}, Data: {uds_data.hex()}")
        
        if service_id == 0x27:
            self.handle_security_access(session_id, can_msg)
        else:
            self.logger.debug(f"Unhandled UDS service 0x{service_id:02X} from {session_id}")
            # 지원하지 않는 서비스 에러 응답
            self.send_uds_error(session_id, service_id, 0x11)  # Service not supported
    
    def handle_security_access(self, session_id, can_msg):
        data = can_msg.data
        
        if len(data) < 3:
            self.send_uds_error(session_id, 0x27, 0x13)
            return
            
        sub_function = data[2]
        security_manager = self.security_managers.get(session_id)
        
        if not security_manager:
            self.send_uds_error(session_id, 0x27, 0x22)
            return
        
        if sub_function in [0x01, 0x03]:
            accessible, message = security_manager.is_level_accessible(sub_function)
            if not accessible:
                self.logger.warning(f"[{session_id}] Security access denied for level 0x{sub_function:02X}: {message}")
                self.send_uds_error(session_id, 0x27, 0x37)
                return
                
            seed = security_manager.generate_seed(sub_function)
            if seed is not None:
                response1_data = struct.pack('>BBBH', 0x10, 0x67, sub_function, (seed >> 16) & 0xFFFF)
                response1_data += b'\x00\x00\x00'
                response1 = CANMessage(can_id=0x7E8, data=response1_data[:8])
                
                response2_data = struct.pack('>BH', 0x21, seed & 0xFFFF)
                response2_data += b'\x00\x00\x00\x00\x00'
                response2 = CANMessage(can_id=0x7E8, data=response2_data[:8])
                
                self.send_to_session(session_id, response1)
                time.sleep(0.01)
                self.send_to_session(session_id, response2)
                
                self.logger.info(f"[{session_id}] Sent seed for level 0x{sub_function:02X}: 0x{seed:08X} (multi-frame)")
            else:
                self.send_uds_error(session_id, 0x27, 0x31)
                
        elif sub_function in [0x02, 0x04]:
            if len(data) < 7:
                self.send_uds_error(session_id, 0x27, 0x13)
                return
                
            provided_key = struct.unpack('>I', data[3:7])[0]
            level = sub_function - 1
            
            success, message = security_manager.verify_key(level, provided_key)
            
            if success:
                response_data = struct.pack('>BBB', 0x03, 0x67, sub_function)
                response_data += b'\x00\x00\x00\x00\x00'
                response = CANMessage(can_id=0x7E8, data=response_data[:8])
                self.send_to_session(session_id, response)
                self.logger.info(f"[{session_id}] Security access granted for level 0x{level:02X}")
            else:
                self.logger.warning(f"[{session_id}] Security access failed for level 0x{level:02X}: {message}")
                if "too many attempts" in message or "timeout" in message:
                    self.send_uds_error(session_id, 0x27, 0x36)
                else:
                    self.send_uds_error(session_id, 0x27, 0x35)
        else:
            self.send_uds_error(session_id, 0x27, 0x12)
    
    def handle_engine_access(self, session_id, can_msg):
        security_manager = self.security_managers.get(session_id)
        if not security_manager:
            self.logger.warning(f"No security manager for {session_id}")
            return
            
        if not security_manager.security_levels[0x03]['unlocked']:
            self.logger.warning(f"[{session_id}] Unauthorized engine access attempt")
            error_response = CANMessage(can_id=0x7E8, data=bytes([0x03, 0x7F, 0x22, 0x33, 0x00, 0x00, 0x00, 0x00]))
            self.send_to_session(session_id, error_response)
            return
        
        self.logger.info(f"[{session_id}] Authorized engine access - forwarding to engine ECU")
        self.forward_to_engine(session_id, can_msg)
    
    def send_uds_error(self, session_id, service_id, error_code):
        # 특별한 에러 코드들에 대해 미묘한 힌트 포함
        if error_code == 0x36:  # Too many attempts
            # 에러 응답의 추가 바이트에 힌트 숨기기
            error_data = struct.pack('>BBBB', 0x03, 0x7F, service_id, error_code)
            error_data += struct.pack('>BBBB', 0x0A, 0x00, 0x1E, 0x00)  # 0x0A=10초, 0x1E=30초
            error_response = CANMessage(can_id=0x7E8, data=error_data[:8])
            self.send_to_session(session_id, error_response)
            
        elif error_code == 0x37:  # Time delay  
            # 대기 시간을 바이트로 힌트
            error_data = struct.pack('>BBBB', 0x03, 0x7F, service_id, error_code)
            error_data += struct.pack('>BBBB', 0x1E, 0x00, 0x00, 0x00)  # 0x1E = 30초
            error_response = CANMessage(can_id=0x7E8, data=error_data[:8])
            self.send_to_session(session_id, error_response)
            
        else:
            # 일반 에러 응답
            error_data = struct.pack('>BBBB', 0x03, 0x7F, service_id, error_code)
            error_data += b'\x00\x00\x00\x00'
            error_response = CANMessage(can_id=0x7E8, data=error_data[:8])
            self.send_to_session(session_id, error_response)
        
        error_names = {
            0x12: "Sub-function not supported",
            0x13: "Incorrect message length", 
            0x22: "Conditions not correct",
            0x31: "Request out of range",
            0x33: "Security access denied",
            0x35: "Invalid key - Check your calculation",
            0x36: "Exceeded number of attempts - Seeds expire in 10s, use automation!",
            0x37: "Required time delay not expired - Wait 30s or start new session"
        }
        
        error_name = error_names.get(error_code, f"Unknown error 0x{error_code:02X}")
        self.logger.info(f"[{session_id}] UDS Error: {error_name}")
    
    def forward_to_engine(self, session_id, can_msg):
        self.logger.info(f"[{session_id}] Forwarding message to engine ECU: ID=0x{can_msg.can_id:03X}, Data={can_msg.data.hex()}")
        
        # Engine ECU가 연결되어 있는지 확인
        engine_session = 'engine_shared'
        if engine_session in self.sessions:
            # Engine ECU에 메시지 전달
            forward_msg = {
                'type': 'forward',
                'original_session': session_id,
                'can_id': can_msg.can_id,
                'data': can_msg.data.hex(),
                'timestamp': can_msg.timestamp
            }
            
            success = self.send_raw_message(engine_session, json.dumps(forward_msg))
            if success:
                self.logger.info(f"[{session_id}] Message successfully forwarded to engine ECU")
            else:
                self.logger.error(f"[{session_id}] Failed to forward message to engine ECU")
                # 에러 응답
                error_response = CANMessage(can_id=0x458, data=bytes([0x7F, 0x22, 0x22]))  # Conditions not correct
                self.send_to_session(session_id, error_response)
        else:
            self.logger.warning(f"[{session_id}] Engine ECU not connected")
            # Engine ECU 연결 안됨 응답
            error_response = CANMessage(can_id=0x458, data=bytes([0x7F, 0x22, 0x22]))  # Conditions not correct
            self.send_to_session(session_id, error_response)
    
    def handle_engine_response(self, session_id, can_msg):
        """Engine ECU로부터 받은 응답을 처리"""
        try:
            msg_data = json.loads(can_msg)
            if msg_data.get('type') == 'engine_response':
                target_session = msg_data['target_session']
                response_can_id = msg_data['can_id']
                response_data = bytes.fromhex(msg_data['data'])
                
                # 원래 세션으로 응답 전달
                response_msg = CANMessage(can_id=response_can_id, data=response_data)
                self.send_to_session(target_session, response_msg)
                
                self.logger.info(f"[{target_session}] Engine response forwarded: ID=0x{response_can_id:03X}, Data={response_data.hex()}")
        except Exception as e:
            self.logger.error(f"Error handling engine response: {e}")
    
    def send_to_session(self, session_id, can_msg):
        if session_id in self.sessions:
            msg_data = {
                'type': 'receive',
                'can_id': can_msg.can_id,
                'data': can_msg.data.hex(),
                'timestamp': can_msg.timestamp
            }
            self.send_raw_message(session_id, json.dumps(msg_data))
        else:
            self.message_queues[session_id].append(can_msg)
    
    def send_raw_message(self, session_id, message):
        try:
            session_info = self.sessions.get(session_id)
            if not session_info:
                return False
                
            socket_obj = session_info['socket']
            socket_obj.send((message + '\n').encode())
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending to {session_id}: {e}")
            if session_id in self.sessions:
                del self.sessions[session_id]
            return False
    
    def send_queued_messages(self, session_id):
        if session_id in self.message_queues:
            for can_msg in self.message_queues[session_id]:
                self.send_to_session(session_id, can_msg)
            self.message_queues[session_id].clear()
    
    def stats_reporter(self):
        while self.running:
            time.sleep(60)
            if self.sessions:
                self.log_session_stats()
                self.log_security_stats()
    
    def log_session_stats(self):
        total_sessions = len(self.sessions)
        infotainment_count = sum(1 for s in self.sessions.values() if s['type'] == 'infotainment')
        engine_count = sum(1 for s in self.sessions.values() if s['type'] == 'engine')
        
        self.logger.info(f"Session Stats: Total={total_sessions}, Infotainment={infotainment_count}, Engine={engine_count}")
    
    def log_security_stats(self):
        security_stats = {}
        for session_id, manager in self.security_managers.items():
            unlocked_levels = sum(1 for level_info in manager.security_levels.values() if level_info['unlocked'])
            total_attempts = sum(level_info['attempts'] for level_info in manager.security_levels.values())
            
            security_stats[session_id] = {
                'unlocked_levels': unlocked_levels,
                'total_attempts': total_attempts,
                'prng_counter': manager.prng.counter
            }
        
        if security_stats:
            self.logger.info(f"Security Stats: {len(security_stats)} sessions with security managers")
            for session_id, stats in security_stats.items():
                self.logger.debug(f"  {session_id}: {stats['unlocked_levels']}/2 levels unlocked, {stats['total_attempts']} attempts, PRNG: {stats['prng_counter']}")
    
    def stop(self):
        self.logger.info("Stopping Advanced CAN Broker...")
        self.running = False
        
        for session_id, info in list(self.sessions.items()):
            try:
                info['socket'].close()
            except:
                pass
        
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
            
        self.logger.info("Advanced CAN Broker stopped")

if __name__ == "__main__":
    broker = CANBroker()
    try:
        broker.start()
    except KeyboardInterrupt:
        broker.logger.info("Received interrupt signal")
        broker.stop()
    except Exception as e:
        broker.logger.error(f"Fatal error: {e}")
        broker.stop()