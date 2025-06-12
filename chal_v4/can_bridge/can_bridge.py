#!/usr/bin/env python3
import socket
import threading
import struct
import time
import logging
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CANBridge:
    def __init__(self, port=12345):
        self.port = port
        self.clients = {}
        self.message_log = []
        self.lock = threading.Lock()
        
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(10)
        
        logger.info(f"CAN Bridge listening on port {self.port}")
        
        while True:
            try:
                client, addr = server.accept()
                logger.info(f"New ECU connection from {addr}")
                
                thread = threading.Thread(target=self.handle_ecu, args=(client, addr))
                thread.daemon = True
                thread.start()
            except Exception as e:
                logger.error(f"Accept error: {e}")
    
    def handle_ecu(self, client, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        
        try:
            # ECU 타입 수신
            client.settimeout(5.0)
            ecu_type = client.recv(32).decode().strip()
            client.settimeout(None)
            
            with self.lock:
                self.clients[client_id] = {
                    'socket': client,
                    'type': ecu_type,
                    'addr': addr
                }
            
            logger.info(f"Registered {ecu_type} from {addr}")
            
            while True:
                # CAN 프레임 수신: [ID(4)][DLC(1)][DATA(8)]
                data = client.recv(13)
                if not data or len(data) != 13:
                    break
                
                can_id, dlc = struct.unpack('>IB', data[:5])
                can_data = data[5:5+dlc]
                
                # 로깅
                logger.info(f"CAN: {ecu_type} -> ID:0x{can_id:03X} DLC:{dlc} Data:{can_data.hex()}")
                
                # 메시지 저장
                message = {
                    'timestamp': time.time(),
                    'sender': ecu_type,
                    'can_id': can_id,
                    'dlc': dlc,
                    'data': can_data
                }
                self.message_log.append(message)
                
                # 다른 ECU들에게 브로드캐스트
                self.broadcast_message(data, exclude=client_id)
                
        except socket.timeout:
            logger.error(f"Timeout waiting for ECU type from {addr}")
        except Exception as e:
            logger.error(f"ECU {client_id} error: {e}")
        finally:
            with self.lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            client.close()
            logger.info(f"ECU {ecu_type} disconnected")
    
    def broadcast_message(self, data, exclude=None):
        """모든 연결된 ECU에게 메시지 전송"""
        with self.lock:
            failed_clients = []
            
            for client_id, client_info in self.clients.items():
                if client_id != exclude:
                    try:
                        client_info['socket'].send(data)
                    except:
                        failed_clients.append(client_id)
            
            # 실패한 클라이언트 제거
            for client_id in failed_clients:
                logger.warning(f"Removing failed client {client_id}")
                del self.clients[client_id]

if __name__ == "__main__":
    bridge = CANBridge()
    bridge.start()