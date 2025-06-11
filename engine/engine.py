import can
import time
import os

class EngineECU:
    def __init__(self):
        self.bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
        self.secret_unlocked = False
        
    def handle_diagnostic_session(self, data):
        """진단 세션 처리"""
        if len(data) >= 2:
            session_type = data[1]
            if session_type == 0x03:  # Extended diagnostic session
                return bytes([0x50, 0x03])
        return bytes([0x7F, 0x10, 0x12])
    
    def handle_read_data(self, data):
        """데이터 읽기 처리"""
        if not self.secret_unlocked:
            return bytes([0x7F, 0x22, 0x33])  # Security access denied
            
        if len(data) >= 3:
            did = (data[1] << 8) | data[2]  # Data Identifier
            
            if did == 0xF190:  # VIN
                vin = b"CTF{FAKE_VIN_12345}"
                return bytes([0x62, 0xF1, 0x90]) + vin
            elif did == 0x1337:  # Secret data
                flag = b"CTF{engine_ecu_compromised_final_flag}"
                return bytes([0x62, 0x13, 0x37]) + flag
                
        return bytes([0x7F, 0x22, 0x31])  # Request out of range
    
    def process_message(self, msg):
        """CAN 메시지 처리"""
        if msg.arbitration_id == 0x700:  # Gateway to Engine
            if len(msg.data) >= 2:
                service = msg.data[0]
                
                response_data = None
                if service == 0x10:  # Diagnostic Session Control
                    response_data = self.handle_diagnostic_session(msg.data)
                    if msg.data[1] == 0x03:  # Extended session unlocks secret
                        self.secret_unlocked = True
                elif service == 0x22:  # Read Data By Identifier
                    response_data = self.handle_read_data(msg.data)
                
                if response_data:
                    response_msg = can.Message(
                        arbitration_id=0x701,  # Engine to Gateway
                        data=response_data
                    )
                    self.bus.send(response_msg)
    
    def run(self):
        """메인 루프"""
        print("Engine ECU started")
        
        for msg in self.bus:
            try:
                self.process_message(msg)
            except Exception as e:
                print(f"Error processing message: {e}")

if __name__ == "__main__":
    engine = EngineECU()
    engine.run()
