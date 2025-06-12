#!/usr/bin/env python3
import socket
import struct
import threading
import logging
import hashlib

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EngineControlModule:
    def __init__(self):
        self.can_socket = None
        self.running = True
        self.unlocked = False
        self.secret_sequence = [0x31, 0x01, 0xDF, 0xFE]  # From Gateway
        
    def connect_to_can(self):
        """CAN Bridge 연결"""
        try:
            self.can_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.can_socket.connect(('can_bridge', 12345))
            self.can_socket.send(b"ENGINE_ECU\n")
            logger.info("ECM connected to CAN Bridge")
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
            logger.info(f"ECM TX: ID=0x{can_id:03X} Data={data.hex()}")
            return True
        except Exception as e:
            logger.error(f"Send error: {e}")
            return False
    
    def handle_routine_control(self, data):
        """Routine Control (0x31) 처리 - Stage 5"""
        if len(data) < 4:
            return
        
        # Gateway에서 온 특별 시퀀스 확인
        if list(data[:4]) == self.secret_sequence:
            logger.info("Secret sequence received! ECM unlocked!")
            self.unlocked = True
            
            # 잠금 해제 확인 메시지
            self.send_can_message(0x7E8, b'\x71\x01\xDF\xFE\x00')
            
            # 특별 진단 모드 활성화
            self.send_can_message(0x600, b'ECM_UNLK')
    
    def handle_read_data(self, data):
        """Read Data By Identifier (0x22) 처리"""
        if not self.unlocked:
            self.send_can_message(0x7E8, b'\x7F\x22\x33')
            return
        
        if len(data) < 3:
            return
        
        did = struct.unpack('>H', data[1:3])[0]
        
        # Stage 5: 특별 DID로 플래그 읽기
        if did == 0xF190:  # VIN
            vin = b'YISF2024ECUTFWIN'
            response = b'\x62' + data[1:3] + vin
            self.send_can_message(0x7E8, response[:8])
            
        elif did == 0xF1A0:  # Secret Data
            # 최종 플래그!
            flag_hash = hashlib.sha256(b'ECU_MASTER_KEY').hexdigest()[:16]
            response = b'\x62' + data[1:3] + flag_hash.encode()[:5]
            self.send_can_message(0x7E8, response)
            
            # 축하 메시지와 플래그
            logger.info("="*50)
            logger.info("CONGRATULATIONS! All stages completed!")
            logger.info("Final Flag: FLAG{ECU_M4st3r_H4ck3r_2024}")
            logger.info("="*50)
            
            # 플래그 파일 생성
            with open('/tmp/final_flag.txt', 'w') as f:
                f.write('FLAG{ECU_M4st3r_H4ck3r_2024}\n')
                f.write('Congratulations on completing all stages!\n')
        else:
            self.send_can_message(0x7E8, b'\x7F\x22\x31')
    
    def can_receive_loop(self):
        """CAN 메시지 수신 루프"""
        while self.running:
            try:
                frame = self.can_socket.recv(13)
                if len(frame) != 13:
                    continue
                
                can_id, dlc = struct.unpack('>IB', frame[:5])
                data = frame[5:5+dlc]
                
                logger.info(f"ECM RX: ID=0x{can_id:03X} Data={data.hex()}")
                
                # ECM 전용 ID (0x7E0) 또는 브로드캐스트 (0x7DF)
                if can_id == 0x7E0 or can_id == 0x7DF:
                    service_id = data[0]
                    
                    if service_id == 0x31:  # Routine Control
                        self.handle_routine_control(data)
                    elif service_id == 0x22:  # Read Data By Identifier
                        self.handle_read_data(data)
                    elif service_id == 0x3E:  # Tester Present
                        self.send_can_message(0x7E8, b'\x7E\x00')
                    else:
                        # 지원하지 않는 서비스
                        self.send_can_message(0x7E8, bytes([0x7F, service_id, 0x11]))
                        
            except Exception as e:
                logger.error(f"Receive error: {e}")
                break
    
    def run(self):
        """ECM 실행"""
        if not self.connect_to_can():
            return
        
        # 수신 스레드 시작
        receive_thread = threading.Thread(target=self.can_receive_loop)
        receive_thread.daemon = True
        receive_thread.start()
        
        logger.info("Engine Control Module running...")
        logger.info("Waiting for unlock sequence...")
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self.running = False
        
        if self.can_socket:
            self.can_socket.close()

if __name__ == "__main__":
    ecm = EngineControlModule()
    ecm.run()