import can
import struct
import time
import hashlib
from threading import Thread

class GatewayECU:
    def __init__(self):
        self.bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
        self.authenticated_sessions = {}
        self.session_timeout = 300  # 5분
        
    def generate_seed(self):
        """취약한 시드 생성 - 시간 기반으로 예측 가능"""
        return int(time.time()) & 0xFFFF
    
    def calculate_key(self, seed):
        """취약한 키 계산 - 간단한 XOR 연산"""
        return seed ^ 0x1337
    
    def handle_security_access(self, data):
        """보안 접근 처리"""
        if len(data) < 2:
            return None
            
        subfunc = data[1]
        
        if subfunc == 0x01:  # Request Seed
            seed = self.generate_seed()
            session_id = data[0] if len(data) > 0 else 0x01
            
            # 세션에 시드 저장
            self.authenticated_sessions[session_id] = {
                'seed': seed,
                'authenticated': False,
                'timestamp': time.time()
            }
            
            return bytes([0x67, 0x01]) + struct.pack('>H', seed)
            
        elif subfunc == 0x02:  # Send Key
            if len(data) < 4:
                return bytes([0x7F, 0x27, 0x13])  # Incorrect message length
                
            session_id = data[0] if len(data) > 2 else 0x01
            provided_key = struct.unpack('>H', data[2:4])[0]
            
            if session_id in self.authenticated_sessions:
                session = self.authenticated_sessions[session_id]
                expected_key = self.calculate_key(session['seed'])
                
                if provided_key == expected_key:
                    session['authenticated'] = True
                    return bytes([0x67, 0x02])
                else:
                    return bytes([0x7F, 0x27, 0x35])  # Invalid key
            else:
                return bytes([0x7F, 0x27, 0x24])  # Request sequence error
    
    def handle_routine_control(self, data):
        """루틴 제어 처리"""
        if len(data) < 4:
            return bytes([0x7F, 0x31, 0x13])
            
        session_id = data[0] if len(data) > 0 else 0x01
        
        # 인증 확인
        if session_id not in self.authenticated_sessions or \
           not self.authenticated_sessions[session_id]['authenticated']:
            return bytes([0x7F, 0x31, 0x33])  # Security access denied
            
        subfunc = data[1]
        routine_id = struct.unpack('>H', data[2:4])[0]
        
        if subfunc == 0x01 and routine_id == 0x1234:  # Start routine
            # 엔진 ECU로 메시지 전달
            engine_msg = can.Message(arbitration_id=0x700, data=[0x10, 0x03])
            self.bus.send(engine_msg)
            return bytes([0x71, 0x01, 0x12, 0x34])
            
        return bytes([0x7F, 0x31, 0x31])  # Request out of range
    
    def process_message(self, msg):
        """CAN 메시지 처리"""
        if msg.arbitration_id == 0x123:  # Infotainment to Gateway
            if len(msg.data) >= 2:
                service = msg.data[0]
                
                response_data = None
                if service == 0x27:  # Security Access
                    response_data = self.handle_security_access(msg.data)
                elif service == 0x31:  # Routine Control
                    response_data = self.handle_routine_control(msg.data)
                
                if response_data:
                    response_msg = can.Message(
                        arbitration_id=0x124,  # Gateway to Infotainment
                        data=response_data
                    )
                    self.bus.send(response_msg)
    
    def run(self):
        """메인 루프"""
        print("Gateway ECU started")
        
        for msg in self.bus:
            try:
                self.process_message(msg)
            except Exception as e:
                print(f"Error processing message: {e}")

if __name__ == "__main__":
    gateway = GatewayECU()
    gateway.run()
