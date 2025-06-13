import socket
import threading
import json
import time
import struct
from collections import defaultdict

class CANMessage:
    """CAN 메시지 구조체"""
    def __init__(self, can_id, data, timestamp=None):
        self.can_id = can_id
        self.data = data
        self.timestamp = timestamp or time.time()
    
    def to_dict(self):
        return {
            'can_id': self.can_id,
            'data': self.data.hex() if isinstance(self.data, bytes) else self.data,
            'timestamp': self.timestamp
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            can_id=data['can_id'],
            data=bytes.fromhex(data['data']) if isinstance(data['data'], str) else data['data'],
            timestamp=data.get('timestamp', time.time())
        )

class CANBroker:
    """CAN 메시지 브로커 - 세션별 메시지 라우팅"""
    
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.sessions = {}  # session_id -> {'socket': socket, 'type': 'infotainment/engine'}
        self.message_queues = defaultdict(list)  # session_id -> [messages]
        self.gateway_state = {}  # 게이트웨이 상태 (인증된 세션 등)
        self.running = False
        
    def start(self):
        """브로커 서버 시작"""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        
        print(f"CAN Broker started on {self.host}:{self.port}")
        
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, addr)
                )
                thread.daemon = True
                thread.start()
            except Exception as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
    
    def handle_client(self, client_socket, addr):
        """클라이언트 연결 처리"""
        session_id = None
        try:
            # 초기 핸드셰이크 - 세션 등록
            data = client_socket.recv(1024).decode()
            handshake = json.loads(data)
            
            session_id = handshake['session_id']
            client_type = handshake['type']  # 'infotainment' or 'engine'
            
            self.sessions[session_id] = {
                'socket': client_socket,
                'type': client_type,
                'addr': addr
            }
            
            # 핸드셰이크 응답
            response = {'status': 'connected', 'session_id': session_id}
            client_socket.send(json.dumps(response).encode() + b'\n')
            
            print(f"Session {session_id} ({client_type}) connected from {addr}")
            
            # 메시지 수신 루프
            buffer = ""
            while self.running:
                data = client_socket.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        self.process_message(session_id, line.strip())
                        
        except Exception as e:
            print(f"Error handling client {addr}: {e}")
        finally:
            if session_id and session_id in self.sessions:
                del self.sessions[session_id]
                print(f"Session {session_id} disconnected")
            client_socket.close()
    
    def process_message(self, session_id, message):
        """CAN 메시지 처리 및 라우팅"""
        try:
            msg_data = json.loads(message)
            
            if msg_data['type'] == 'send':
                # CAN 메시지 전송
                can_msg = CANMessage(
                    can_id=msg_data['can_id'],
                    data=bytes.fromhex(msg_data['data'])
                )
                self.route_message(session_id, can_msg)
                
            elif msg_data['type'] == 'dump_start':
                # candump 시작 - 큐에 쌓인 메시지들 전송
                self.send_queued_messages(session_id)
                
        except Exception as e:
            print(f"Error processing message from {session_id}: {e}")
    
    def route_message(self, sender_session, can_msg):
        """메시지 라우팅 로직"""
        sender_info = self.sessions.get(sender_session)
        if not sender_info:
            return
        
        # 게이트웨이 로직
        if sender_info['type'] == 'infotainment':
            # 인포테인먼트에서 온 메시지
            if can_msg.can_id == 0x123:  # 게이트웨이와의 통신
                # 게이트웨이 인증 처리
                response = self.handle_gateway_auth(sender_session, can_msg)
                if response:
                    self.send_to_session(sender_session, response)
            
            elif can_msg.can_id == 0x456 and self.is_authenticated(sender_session):
                # 인증된 세션만 엔진 ECU에 접근 가능
                self.forward_to_engine(sender_session, can_msg)
        
        elif sender_info['type'] == 'engine':
            # 엔진에서 온 응답 메시지 - 원래 요청한 세션으로 전달
            target_session = self.find_target_session(can_msg)
            if target_session:
                self.send_to_session(target_session, can_msg)
    
    def handle_gateway_auth(self, session_id, can_msg):
        """게이트웨이 인증 처리"""
        if len(can_msg.data) >= 4:
            # 간단한 시드-키 알고리즘 (취약점 포함)
            seed = struct.unpack('>I', can_msg.data[:4])[0]
            key = (seed ^ 0xDEADBEEF) & 0xFFFFFFFF  # 예측 가능한 키 생성
            
            # 세션 인증 상태 업데이트
            self.gateway_state[session_id] = {
                'authenticated': True,
                'timestamp': time.time()
            }
            
            # 인증 성공 응답
            response_data = struct.pack('>I', key)
            return CANMessage(can_id=0x124, data=response_data)
        
        return None
    
    def is_authenticated(self, session_id):
        """세션 인증 상태 확인"""
        auth_info = self.gateway_state.get(session_id)
        if not auth_info:
            return False
        
        # 인증 타임아웃 (5분)
        if time.time() - auth_info['timestamp'] > 300:
            del self.gateway_state[session_id]
            return False
        
        return auth_info['authenticated']
    
    def forward_to_engine(self, session_id, can_msg):
        """엔진 ECU로 메시지 전달"""
        # 엔진 ECU 세션 찾기
        engine_session = None
        for sid, info in self.sessions.items():
            if info['type'] == 'engine':
                engine_session = sid
                break
        
        if engine_session:
            # 메시지에 원본 세션 정보 추가
            modified_msg = {
                'type': 'forward',
                'original_session': session_id,
                'can_id': can_msg.can_id,
                'data': can_msg.data.hex(),
                'timestamp': can_msg.timestamp
            }
            self.send_raw_message(engine_session, json.dumps(modified_msg))
    
    def send_to_session(self, session_id, can_msg):
        """특정 세션에 CAN 메시지 전송"""
        if session_id in self.sessions:
            msg_data = {
                'type': 'receive',
                'can_id': can_msg.can_id,
                'data': can_msg.data.hex(),
                'timestamp': can_msg.timestamp
            }
            self.send_raw_message(session_id, json.dumps(msg_data))
        else:
            # 세션이 없으면 큐에 저장
            self.message_queues[session_id].append(can_msg)
    
    def send_raw_message(self, session_id, message):
        """raw 메시지 전송"""
        try:
            socket_obj = self.sessions[session_id]['socket']
            socket_obj.send((message + '\n').encode())
        except Exception as e:
            print(f"Error sending message to {session_id}: {e}")
    
    def send_queued_messages(self, session_id):
        """큐에 쌓인 메시지들 전송"""
        if session_id in self.message_queues:
            for can_msg in self.message_queues[session_id]:
                self.send_to_session(session_id, can_msg)
            self.message_queues[session_id].clear()
    
    def find_target_session(self, can_msg):
        """엔진 응답의 타겟 세션 찾기"""
        # 실제로는 메시지 내용을 파싱해서 원본 세션 ID 추출
        # 여기서는 간단히 구현
        return None
    
    def stop(self):
        """브로커 종료"""
        self.running = False
        if hasattr(self, 'server_socket'):
            self.server_socket.close()

if __name__ == "__main__":
    broker = CANBroker()
    try:
        broker.start()
    except KeyboardInterrupt:
        print("\nShutting down CAN broker...")
        broker.stop()