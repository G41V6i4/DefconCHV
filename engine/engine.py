#!/usr/bin/env python3
"""
엔진 ECU - Custom CAN 브로커와 호환되는 버전
최종 목표 플래그 보관
"""
import socket
import json
import time
import threading
import struct

class EngineECU:
    def __init__(self):
        self.secret_flag = "CTF{engine_ecu_compromised_final_flag}"
        self.diagnostic_mode = False
        self.secret_unlocked = False
        self.session_states = {}  # 세션별 상태 관리
        
    def start(self):
        print("Engine ECU starting...")
        
        # CAN 브로커에 연결
        while True:
            try:
                self.connect_to_broker()
                break
            except Exception as e:
                print(f"Waiting for CAN broker: {e}")
                time.sleep(2)
    
    def connect_to_broker(self):
        """CAN 브로커에 연결"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect(('gateway_shared', 9999))
        
        # 핸드셰이크
        handshake = {
            'session_id': 'engine_shared',
            'type': 'engine'
        }
        self.sock.send(json.dumps(handshake).encode())
        
        # 응답 대기
        response = self.sock.recv(1024).decode().strip()
        print(f"Connected to CAN broker: {response}")
        
        # 메시지 수신 루프
        buffer = ""
        while True:
            try:
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        self.process_broker_message(line.strip())
                        
            except Exception as e:
                print(f"Connection error: {e}")
                break
    
    def process_broker_message(self, message):
        """브로커에서 받은 메시지 처리"""
        try:
            msg_data = json.loads(message)
            
            if msg_data['type'] == 'forward':
                # 게이트웨이를 통해 전달된 메시지
                original_session = msg_data['original_session']
                can_id = msg_data['can_id']
                data = bytes.fromhex(msg_data['data'])
                
                print(f"Received CAN message from {original_session}: ID=0x{can_id:03X}, Data={data.hex()}")
                
                # UDS 메시지 처리
                response = self.handle_uds_message(original_session, can_id, data)
                if response:
                    self.send_response(original_session, response)
                    
        except Exception as e:
            print(f"Error processing broker message: {e}")
    
    def handle_uds_message(self, session_id, can_id, data):
        """UDS (Unified Diagnostic Services) 메시지 처리"""
        if can_id != 0x456:  # 엔진으로 전달되는 CAN ID
            return None
            
        if len(data) < 1:
            return None
        
        # 세션별 상태 초기화
        if session_id not in self.session_states:
            self.session_states[session_id] = {
                'diagnostic_mode': False,
                'secret_unlocked': False
            }
        
        session_state = self.session_states[session_id]
        service_id = data[0]
        
        print(f"Processing UDS service 0x{service_id:02X} for session {session_id}")
        
        if service_id == 0x10:  # Diagnostic Session Control
            return self.handle_diagnostic_session(session_id, data)
        elif service_id == 0x27:  # Security Access
            return self.handle_security_access(session_id, data)
        elif service_id == 0x22:  # Read Data by Identifier
            return self.handle_read_data(session_id, data)
        else:
            # 지원하지 않는 서비스
            return {
                'can_id': 0x4A1,  # 엔진 응답 CAN ID
                'data': bytes([0x7F, service_id, 0x11])  # Service not supported
            }
    
    def handle_diagnostic_session(self, session_id, data):
        """진단 세션 제어"""
        if len(data) >= 2:
            session_type = data[1]
            session_state = self.session_states[session_id]
            
            if session_type == 0x01:  # Default Session
                session_state['diagnostic_mode'] = False
                session_state['secret_unlocked'] = False
                return {
                    'can_id': 0x4A1,
                    'data': bytes([0x50, 0x01])  # Positive response
                }
            elif session_type == 0x03:  # Extended Diagnostic Session
                session_state['diagnostic_mode'] = True
                print(f"Session {session_id} entered diagnostic mode")
                return {
                    'can_id': 0x4A1,
                    'data': bytes([0x50, 0x03])  # Positive response
                }
        
        return {
            'can_id': 0x4A1,
            'data': bytes([0x7F, 0x10, 0x12])  # Sub-function not supported
        }
    
    def handle_security_access(self, session_id, data):
        """보안 접근 제어"""
        session_state = self.session_states[session_id]
        
        if not session_state['diagnostic_mode']:
            return {
                'can_id': 0x4A1,
                'data': bytes([0x7F, 0x27, 0x22])  # Conditions not correct
            }
        
        if len(data) >= 2:
            sub_function = data[1]
            
            if sub_function == 0x01:  # Request Seed
                # 고정된 시드 제공 (취약점)
                seed = struct.pack('>H', 0x1337)
                print(f"Sending seed to session {session_id}: 0x1337")
                return {
                    'can_id': 0x4A1,
                    'data': bytes([0x67, 0x01]) + seed
                }
            
            elif sub_function == 0x02 and len(data) >= 4:  # Send Key
                key = struct.unpack('>H', data[2:4])[0]
                expected_key = 0x1337 ^ 0xCAFE  # 간단한 키 알고리즘
                
                print(f"Session {session_id} sent key: 0x{key:04X}, expected: 0x{expected_key:04X}")
                
                if key == expected_key:
                    session_state['secret_unlocked'] = True
                    print(f"Session {session_id} security unlocked!")
                    return {
                        'can_id': 0x4A1,
                        'data': bytes([0x67, 0x02])  # Security unlocked
                    }
                else:
                    return {
                        'can_id': 0x4A1,
                        'data': bytes([0x7F, 0x27, 0x35])  # Invalid key
                    }
        
        return {
            'can_id': 0x4A1,
            'data': bytes([0x7F, 0x27, 0x12])  # Sub-function not supported
        }
    
    def handle_read_data(self, session_id, data):
        """데이터 읽기"""
        session_state = self.session_states[session_id]
        
        if not session_state['secret_unlocked']:
            return {
                'can_id': 0x4A1,
                'data': bytes([0x7F, 0x22, 0x33])  # Security access denied
            }
        
        if len(data) >= 3:
            did = struct.unpack('>H', data[1:3])[0]  # Data Identifier
            
            print(f"Session {session_id} reading DID: 0x{did:04X}")
            
            if did == 0xF190:  # Vehicle Identification Number
                vin_data = b"CTF_TEST_VIN_123"
                return {
                    'can_id': 0x4A1,
                    'data': bytes([0x62, 0xF1, 0x90]) + vin_data[:10]  # 길이 제한
                }
            
            elif did == 0xF1A0:  # Secret Flag DID
                print(f"🎉 Session {session_id} found the secret flag!")
                flag_data = self.secret_flag.encode()
                
                # 긴 데이터는 여러 메시지로 분할 (실제로는 ISO-TP 사용)
                if len(flag_data) <= 5:  # CAN 데이터 길이 제한 (8바이트 - 3바이트 헤더)
                    return {
                        'can_id': 0x4A1,
                        'data': bytes([0x62, 0xF1, 0xA0]) + flag_data
                    }
                else:
                    # 첫 번째 청크만 반환
                    return {
                        'can_id': 0x4A1,
                        'data': bytes([0x62, 0xF1, 0xA0]) + flag_data[:5]
                    }
            
            elif did == 0x1337:  # Alternative secret access
                secret_data = b"SECRET"
                return {
                    'can_id': 0x4A1,
                    'data': bytes([0x62, 0x13, 0x37]) + secret_data
                }
        
        return {
            'can_id': 0x4A1,
            'data': bytes([0x7F, 0x22, 0x31])  # Request out of range
        }
    
    def send_response(self, target_session, response):
        """응답 메시지 전송"""
        try:
            response_msg = {
                'type': 'engine_response',
                'target_session': target_session,
                'can_id': response['can_id'],
                'data': response['data'].hex(),
                'timestamp': time.time()
            }
            
            self.sock.send((json.dumps(response_msg) + '\n').encode())
            print(f"Sent response to {target_session}: ID=0x{response['can_id']:03X}, Data={response['data'].hex()}")
            
        except Exception as e:
            print(f"Error sending response: {e}")

if __name__ == "__main__":
    engine = EngineECU()
    try:
        engine.start()
    except KeyboardInterrupt:
        print("\nEngine ECU stopping...")
    except Exception as e:
        print(f"Engine ECU error: {e}")