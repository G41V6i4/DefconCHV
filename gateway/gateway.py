#!/usr/bin/env python3
"""
CAN Message Broker for ECU Simulator
게이트웨이 ECU에 내장되어 세션별 CAN 메시지 라우팅을 담당
"""
import socket
import threading
import json
import time
import struct
import logging
from collections import defaultdict
from datetime import datetime

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
        
        # 로깅 설정
        self.setup_logging()
        
    def setup_logging(self):
        """로깅 설정"""
        # 로그 포맷 설정
        log_format = '%(asctime)s [%(levelname)s] %(message)s'
        logging.basicConfig(
            level=logging.INFO,
            format=log_format,
            handlers=[
                logging.StreamHandler(),  # 콘솔 출력
                logging.FileHandler('/tmp/can_broker.log')  # 파일 저장
            ]
        )
        self.logger = logging.getLogger('CANBroker')
        self.logger.info("CAN Broker logging initialized")
        
    def start(self):
        """브로커 서버 시작"""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(10)
            self.logger.info(f"CAN Broker started on {self.host}:{self.port}")
            
            # 통계 쓰레드 시작
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
        """클라이언트 연결 처리"""
        session_id = None
        client_type = None
        
        try:
            # 소켓 타임아웃 설정
            client_socket.settimeout(60)
            
            # 초기 핸드셰이크 - 세션 등록
            self.logger.info(f"Waiting for handshake from {addr}")
            data = client_socket.recv(1024).decode()
            
            if not data:
                self.logger.warning(f"Empty handshake from {addr}")
                return
                
            handshake = json.loads(data)
            session_id = handshake['session_id']
            client_type = handshake['type']
            
            self.logger.info(f"Handshake received: session={session_id}, type={client_type}, addr={addr}")
            
            # 중복 세션 체크
            if session_id in self.sessions:
                self.logger.warning(f"Duplicate session {session_id} from {addr}, replacing existing")
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
            
            # 핸드셰이크 응답
            response = {'status': 'connected', 'session_id': session_id}
            client_socket.send(json.dumps(response).encode() + b'\n')
            
            self.logger.info(f"Session {session_id} ({client_type}) connected from {addr}")
            self.log_session_stats()
            
            # 메시지 수신 루프
            buffer = ""
            while self.running:
                try:
                    data = client_socket.recv(1024).decode()
                    if not data:
                        self.logger.info(f"Client {session_id} disconnected (no data)")
                        break
                    
                    self.sessions[session_id]['last_activity'] = time.time()
                    buffer += data
                    
                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        if line.strip():
                            self.sessions[session_id]['message_count'] += 1
                            self.process_message(session_id, line.strip())
                            
                except socket.timeout:
                    self.logger.warning(f"Timeout for session {session_id}")
                    break
                except Exception as e:
                    self.logger.error(f"Error receiving from {session_id}: {e}")
                    break
                        
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid handshake JSON from {addr}: {e}")
        except Exception as e:
            self.logger.error(f"Error handling client {addr}: {e}")
        finally:
            if session_id and session_id in self.sessions:
                self.logger.info(f"Cleaning up session {session_id}")
                del self.sessions[session_id]
                self.log_session_stats()
            client_socket.close()
    
    def process_message(self, session_id, message):
        """CAN 메시지 처리 및 라우팅"""
        try:
            msg_data = json.loads(message)
            msg_type = msg_data.get('type', 'unknown')
            
            self.logger.debug(f"Processing message from {session_id}: type={msg_type}")
            
            if msg_type == 'send':
                # CAN 메시지 전송
                can_msg = CANMessage(
                    can_id=msg_data['can_id'],
                    data=bytes.fromhex(msg_data['data'])
                )
                
                self.logger.info(f"CAN message from {session_id}: ID=0x{can_msg.can_id:03X}, Data={can_msg.data.hex()}")
                self.route_message(session_id, can_msg)
                
            elif msg_type == 'dump_start':
                # candump 시작 - 큐에 쌓인 메시지들 전송
                self.logger.info(f"Starting candump for session {session_id}")
                self.send_queued_messages(session_id)
                
            else:
                self.logger.warning(f"Unknown message type '{msg_type}' from {session_id}")
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON from {session_id}: {e}")
        except Exception as e:
            self.logger.error(f"Error processing message from {session_id}: {e}")
    
    def route_message(self, sender_session, can_msg):
        """메시지 라우팅 로직"""
        sender_info = self.sessions.get(sender_session)
        if not sender_info:
            self.logger.error(f"Unknown sender session: {sender_session}")
            return
        
        sender_type = sender_info['type']
        self.logger.info(f"Routing message from {sender_session} ({sender_type}): ID=0x{can_msg.can_id:03X}")
        
        # 게이트웨이 로직
        if sender_type == 'infotainment':
            # 인포테인먼트에서 온 메시지
            if can_msg.can_id == 0x123:  # 게이트웨이와의 통신
                self.logger.info(f"Gateway authentication request from {sender_session}")
                # 게이트웨이 인증 처리
                response = self.handle_gateway_auth(sender_session, can_msg)
                if response:
                    self.logger.info(f"Sending auth response to {sender_session}: ID=0x{response.can_id:03X}")
                    self.send_to_session(sender_session, response)
                else:
                    self.logger.warning(f"Authentication failed for {sender_session}")
            
            elif can_msg.can_id == 0x456 and self.is_authenticated(sender_session):
                # 인증된 세션만 엔진 ECU에 접근 가능
                self.logger.info(f"Forwarding to engine ECU from authenticated session {sender_session}")
                self.forward_to_engine(sender_session, can_msg)
            
            elif can_msg.can_id == 0x456:
                self.logger.warning(f"Unauthorized engine access attempt from {sender_session}")
            
            else:
                self.logger.debug(f"Unhandled CAN ID 0x{can_msg.can_id:03X} from {sender_session}")
        
        elif sender_type == 'engine':
            # 엔진에서 온 응답 메시지 - 원래 요청한 세션으로 전달
            self.logger.info(f"Engine response: ID=0x{can_msg.can_id:03X}")
            target_session = self.find_target_session(can_msg)
            if target_session:
                self.logger.info(f"Forwarding engine response to {target_session}")
                self.send_to_session(target_session, can_msg)
            else:
                self.logger.warning("No target session found for engine response")
    
    def handle_gateway_auth(self, session_id, can_msg):
        """게이트웨이 인증 처리"""
        if len(can_msg.data) >= 4:
            # 간단한 시드-키 알고리즘 (취약점 포함)
            seed = struct.unpack('>I', can_msg.data[:4])[0]
            key = (seed ^ 0xDEADBEEF) & 0xFFFFFFFF  # 예측 가능한 키 생성
            
            self.logger.info(f"Gateway auth: session={session_id}, seed=0x{seed:08X}, key=0x{key:08X}")
            
            # 세션 인증 상태 업데이트
            self.gateway_state[session_id] = {
                'authenticated': True,
                'timestamp': time.time()
            }
            
            self.logger.info(f"Session {session_id} authenticated successfully")
            
            # 인증 성공 응답
            response_data = struct.pack('>I', key)
            return CANMessage(can_id=0x124, data=response_data)
        
        self.logger.warning(f"Invalid auth data length from {session_id}")
        return None
    
    def is_authenticated(self, session_id):
        """세션 인증 상태 확인"""
        auth_info = self.gateway_state.get(session_id)
        if not auth_info:
            self.logger.debug(f"Session {session_id} not authenticated")
            return False
        
        # 인증 타임아웃 (5분)
        if time.time() - auth_info['timestamp'] > 300:
            self.logger.info(f"Session {session_id} authentication expired")
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
            session_info = self.sessions.get(session_id)
            if not session_info:
                self.logger.error(f"Session {session_id} not found for message send")
                return False
                
            socket_obj = session_info['socket']
            socket_obj.send((message + '\n').encode())
            self.logger.debug(f"Sent message to {session_id}: {message[:100]}...")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending message to {session_id}: {e}")
            # 연결이 끊어진 세션 정리
            if session_id in self.sessions:
                del self.sessions[session_id]
            return False
    
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
    
    def stats_reporter(self):
        """주기적 통계 리포팅"""
        while self.running:
            time.sleep(30)  # 30초마다
            if self.sessions:
                self.log_session_stats()
                self.log_auth_stats()
    
    def log_session_stats(self):
        """세션 통계 로깅"""
        total_sessions = len(self.sessions)
        infotainment_count = sum(1 for s in self.sessions.values() if s['type'] == 'infotainment')
        engine_count = sum(1 for s in self.sessions.values() if s['type'] == 'engine')
        
        self.logger.info(f"Session Stats: Total={total_sessions}, Infotainment={infotainment_count}, Engine={engine_count}")
        
        # 개별 세션 정보
        for session_id, info in self.sessions.items():
            uptime = time.time() - info['connected_at']
            inactive_time = time.time() - info['last_activity']
            self.logger.debug(f"  {session_id} ({info['type']}): uptime={uptime:.1f}s, inactive={inactive_time:.1f}s, msgs={info['message_count']}")
    
    def log_auth_stats(self):
        """인증 통계 로깅"""
        auth_count = len(self.gateway_state)
        if auth_count > 0:
            self.logger.info(f"Authenticated sessions: {auth_count}")
            for session_id, auth_info in self.gateway_state.items():
                auth_age = time.time() - auth_info['timestamp']
                self.logger.debug(f"  {session_id}: authenticated {auth_age:.1f}s ago")
    
    def get_status(self):
        """브로커 상태 반환"""
        return {
            'running': self.running,
            'total_sessions': len(self.sessions),
            'authenticated_sessions': len(self.gateway_state),
            'sessions': {
                session_id: {
                    'type': info['type'],
                    'addr': f"{info['addr'][0]}:{info['addr'][1]}",
                    'connected_at': info['connected_at'],
                    'last_activity': info['last_activity'],
                    'message_count': info['message_count']
                }
                for session_id, info in self.sessions.items()
            }
        }

    def stop(self):
        """브로커 종료"""
        self.logger.info("Stopping CAN Broker...")
        self.running = False
        
        # 모든 클라이언트 연결 종료
        for session_id, info in list(self.sessions.items()):
            try:
                info['socket'].close()
            except:
                pass
        
        if hasattr(self, 'server_socket'):
            self.server_socket.close()
            
        self.logger.info("CAN Broker stopped")

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