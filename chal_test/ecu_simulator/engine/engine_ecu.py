#!/usr/bin/env python3
"""
엔진 ECU - 최종 목표 플래그 보관
"""
import socket
import json
import time
import threading
import struct

class EngineECU:
    def __init__(self):
        self.secret_flag = "CTF{ECU_HACKING_COMPLETE_2024}"
        self.diagnostic_mode = False
        
    def start(self):
        print("Engine ECU started")
        
        # CAN 브로커에 연결
        while True:
            try:
                self.connect_to_broker()
                break
            except:
                print("Waiting for CAN broker...")
                time.sleep(2)
    
    def connect_to_broker(self):
        """CAN 브로커에 연결"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 9999))
        
        # 핸드셰이크
        handshake = {
            'session_id': 'engine_shared',
            'type': 'engine'
        }
        sock.send(json.dumps(handshake).encode())
        
        # 응답 대기
        response = sock.recv(1024).decode().strip()
        print(f"Connected to CAN broker: {response}")
        
        # 메시지 수신 루프
        buffer = ""
        while True:
            data = sock.recv(1024).decode()
            if not data:
                break
            
            buffer += data
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line.strip():
                    self.process_can_message(line.strip(), sock)
    
    def process_can_message(self, message, sock):
        """CAN 메시지 처리"""
        try:
            msg_data = json.loads(message)
            
            if msg_data['type'] == 'forward':
                # 게이트웨이를 통해 전달된 메시지
                original_session = msg_data['original_session']
                can_id = msg_data['can_id']
                data = bytes.fromhex(msg_data['data'])
                
                response = self.handle_engine_command(can_id, data)
                if response:
                    # 응답을 원본 세션으로 전송
                    response_msg = {
                        'type': 'engine_response',
                        'target_session': original_session,
                        'can_id': response['can_id'],
                        'data': response['data'].hex(),
                        'timestamp': time.time()
                    }
                    sock.send((json.dumps(response_msg) + '\n').encode())
                    
        except Exception as e:
            print(f"Error processing message: {e}")
    
    def handle_engine_command(self, can_id, data):
        """엔진 명령어 처리"""
        if can_id == 0x7E0:  # UDS 진단 요청
            return self.handle_uds_request(data)
        elif can_id == 0x456:  # 일반 엔진 제어
            return self.handle_engine_control(data)
        
        return None
    
    def handle_uds_request(self, data):
        """UDS (Unified Diagnostic Services) 요청 처리"""
        if len(data) < 1:
            return None
        
        service_id = data[0]
        
        if service_id == 0x10:  # Diagnostic Session Control
            if len(data) >= 2 and data[1] == 0x03:  # Extended Diagnostic Session
                self.diagnostic_mode = True
                return {
                    'can_id': 0x7E8,  # UDS 응답
                    'data': bytes([0x50, 0x03])  # Positive response
                }
        
        elif service_id == 0x27 and self.diagnostic_mode:  # Security Access
            if len(data) >= 2:
                if data[1] == 0x01:  # Request Seed
                    seed = struct.pack('>H', 0x1337)  # 고정 시드 (취약점)
                    return {
                        'can_id': 0x7E8,
                        'data': bytes([0x67, 0x01]) + seed
                    }
                elif data[1] == 0x02 and len(data) >= 4:  # Send Key
                    key = struct.unpack('>H', data[2:4])[0]
                    if key == 0x1337 ^ 0xCAFE:  # 간단한 키 검증
                        return {
                            'can_id': 0x7E8,
                            'data': bytes([0x67, 0x02])  # Security unlocked
                        }
        
        elif service_id == 0x22 and self.diagnostic_mode:  # Read Data by Identifier
            if len(data) >= 3:
                did = struct.unpack('>H', data[1:3])[0]
                if did == 0xF190:  # Vehicle Identification Number
                    return {
                        'can_id': 0x7E8,
                        'data': bytes([0x62, 0xF1, 0x90]) + self.secret_flag.encode()[:5]
                    }
                elif did == 0xF1A0:  # Secret Flag DID
                    return {
                        'can_id': 0x7E8,
                        'data': bytes([0x62, 0xF1, 0xA0]) + self.secret_flag.encode()
                    }
        
        # 기본 부정응답
        return {
            'can_id': 0x7E8,
            'data': bytes([0x7F, service_id, 0x11])  # Service not supported
        }
    
    def handle_engine_control(self, data):
        """일반 엔진 제어 명령"""
        # 간단한 엔진 상태 응답
        return {
            'can_id': 0x4A0,
            'data': bytes([0x01, 0x23, 0x45, 0x67])  # 엔진 상태 데이터
        }

if __name__ == "__main__":
    engine = EngineECU()
    engine.start()
