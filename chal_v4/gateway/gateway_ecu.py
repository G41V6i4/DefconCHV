#!/usr/bin/env python3
import socket
import struct
import threading
import time
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class GatewayECU:
    def __init__(self):
        self.can_socket = None
        self.running = True
        self.sessions = {}  # 인증 세션 관리
        
    def connect_to_can(self):
        """CAN Bridge 연결"""
        try:
            self.can_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.can_socket.connect(('can_bridge', 12345))
            self.can_socket.send(b"GATEWAY_ECU\n")
            logger.info("Gateway ECU connected to CAN Bridge")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to CAN Bridge: {e}")
            return False
    
    def send_can_message(self, can_id, data):
        """CAN 메시지 전송"""
        if not self.can_socket:
            return False
            
        frame = struct.pack('>IB', can_id, len(data))
        frame += data.ljust(8, b'\x00')
        
        try:
            self.can_socket.send(frame)
            logger.info(f"TX: ID=0x{can_id:03X} Data={data.hex()}")
            return True
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False
    
    def handle_diagnostic_request(self, can_id, data):
        """진단 요청 처리"""
        if len(data) < 2:
            return
            
        service_id = data[0]
        sub_function = data[1] if len(data) > 1 else 0
        
        # Stage 3-4: Security Access (0x27)
        if service_id == 0x27:
            if sub_function == 0x01:  # Request Seed
                # 약한 시드 생성
                seed = int(time.time()) & 0xFFFF
                self.sessions[can_id] = {
                    'seed': seed,
                    'authenticated': False,
                    'timestamp': time.time()
                }
                
                response = struct.pack('>BBH', 0x67, 0x01, seed)
                self.send_can_message(can_id + 8, response)
                logger.info(f"Sent seed: 0x{seed:04X}")
                
            elif sub_function == 0x02:  # Send Key
                if can_id not in self.sessions:
                    # Negative response
                    self.send_can_message(can_id + 8, b'\x7F\x27\x35')
                    return
                
                session = self.sessions[can_id]
                if len(data) >= 4:
                    provided_key = struct.unpack('>H', data[2:4])[0]
                    
                    # Stage 4: 약한 키 알고리즘 (XOR with 0x5555)
                    expected_key = session['seed'] ^ 0x5555
                    
                    if provided_key == expected_key:
                        session['authenticated'] = True
                        self.send_can_message(can_id + 8, b'\x67\x02')
                        logger.info("Authentication successful!")
                        
                        # 인증 성공 메시지
                        hint_msg = b"AUTH_OK!"
                        self.send_can_message(0x600, hint_msg)
                    else:
                        self.send_can_message(can_id + 8, b'\x7F\x27\x35')
                        logger.warning(f"Authentication failed. Expected: 0x{expected_key:04X}, Got: 0x{provided_key:04X}")
        
        # Stage 5: Input/Output Control (0x2F)
        elif service_id == 0x2F:
            if can_id in self.sessions and self.sessions[can_id]['authenticated']:
                if len(data) >= 3 and data[1] == 0xF1 and data[2] == 0x90:
                    # Magic sequence detected!
                    logger.info("Magic sequence received! Granting ECM access!")
                    
                    # ECM에 특별 명령 전송
                    ecm_unlock = b'\x31\x01\xDF\xFE'  # Routine Control to ECM
                    self.send_can_message(0x7E0, ecm_unlock)
                    
                    # 성공 응답
                    self.send_can_message(can_id + 8, b'\x6F\xF1\x90')
                    
                    # 플래그 파일 생성
                    with open('/tmp/gateway_flag.txt', 'w') as f:
                        f.write('FLAG{G4t3w4y_Auth_Byp4ss3d}\n')
                else:
                    self.send_can_message(can_id + 8, b'\x7F\x2F\x31')
            else:
                self.send_can_message(can_id + 8, b'\x7F\x2F\x33')  # Security Access Denied
        
        # Tester Present (0x3E)
        elif service_id == 0x3E:
            if can_id in self.sessions:
                self.sessions[can_id]['timestamp'] = time.time()
            self.send_can_message(can_id + 8, b'\x7E\x00')
    
    def can_receive_loop(self):
        """CAN 메시지 수신 루프"""
        while self.running:
            try:
                frame = self.can_socket.recv(13)
                if len(frame) != 13:
                    continue
                
                can_id, dlc = struct.unpack('>IB', frame[:5])
                data = frame[5:5+dlc]
                
                logger.info(f"RX: ID=0x{can_id:03X} Data={data.hex()}")
                
                # 진단 요청 처리 (0x7DF는 브로드캐스트, 0x7E8은 Gateway 전용)
                if can_id == 0x7DF or can_id == 0x7E8:
                    self.handle_diagnostic_request(can_id, data)
                
                # 세션 타임아웃 확인
                current_time = time.time()
                timeout_sessions = []
                for session_id, session in self.sessions.items():
                    if current_time - session['timestamp'] > 30:  # 30초 타임아웃
                        timeout_sessions.append(session_id)
                
                for session_id in timeout_sessions:
                    logger.info(f"Session 0x{session_id:03X} timed out")
                    del self.sessions[session_id]
                    
            except Exception as e:
                logger.error(f"Receive error: {e}")
                break
    
    def run(self):
        """Gateway ECU 실행"""
        # CAN 연결
        if not self.connect_to_can():
            return
        
        # 수신 스레드 시작
        receive_thread = threading.Thread(target=self.can_receive_loop)
        receive_thread.daemon = True
        receive_thread.start()
        
        logger.info("Gateway ECU running...")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.running = False
        
        if self.can_socket:
            self.can_socket.close()

if __name__ == "__main__":
    ecu = GatewayECU()
    ecu.run()