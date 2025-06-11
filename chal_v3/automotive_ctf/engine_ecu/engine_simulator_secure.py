import can
import time
import threading
import struct
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecureEngineECU:
    def __init__(self):
        self.can_interface = os.environ.get('CAN_INTERFACE', 'vcan1')
        self.bus = None
        self.running = False
        self.security_level = 0
        
        with open('/app/secret.txt', 'r') as f:
            self.secret_flag = f.read().strip()
            
    def process_can_message(self, msg):
        if len(msg.data) < 2:
            return
            
        session_id = struct.unpack('>H', msg.data[:2])[0]
        actual_data = msg.data[2:]
        
        # Simple response
        if msg.arbitration_id == 0x7E0:
            response = can.Message(
                arbitration_id=0x7E8,
                data=msg.data[:2] + bytes([0x7F, actual_data[0], 0x33]),
                is_extended_id=False
            )
            self.bus.send(response)
            
    def start(self):
        self.bus = can.interface.Bus(self.can_interface, bustype='socketcan')
        self.running = True
        
        while self.running:
            msg = self.bus.recv(timeout=0.1)
            if msg:
                self.process_can_message(msg)

if __name__ == "__main__":
    ecu = SecureEngineECU()
    ecu.start()
