#!/usr/bin/env python3
"""
CAN 데몬 - 게이트웨이와 지속적 연결 유지
인포테인먼트 컨테이너에서 백그라운드로 실행
"""
import socket
import json
import time
import threading
import os
import queue
from pathlib import Path

class CANDaemon:
    def __init__(self):
        self.session_id = self.get_session_id()
        self.sock = None
        self.running = False
        self.send_queue = queue.Queue()
        self.receive_queue = queue.Queue()
        
        # 로컬 통신용 파이프
        self.pipe_dir = "/tmp/can_daemon"
        Path(self.pipe_dir).mkdir(exist_ok=True)
        self.send_pipe = f"{self.pipe_dir}/send"
        self.recv_pipe = f"{self.pipe_dir}/recv"
        
        # Named pipe 생성 (권한 문제 해결)
        self.create_pipes()
    
    def create_pipes(self):
        """Named pipe 생성 및 권한 설정"""
        try:
            # 기존 파이프 제거
            for pipe in [self.send_pipe, self.recv_pipe]:
                if os.path.exists(pipe):
                    os.unlink(pipe)
            
            # 새 파이프 생성
            os.mkfifo(self.send_pipe, 0o666)
            os.mkfifo(self.recv_pipe, 0o666)
            
            # 권한 명시적 설정
            os.chmod(self.send_pipe, 0o666)
            os.chmod(self.recv_pipe, 0o666)
            
            print(f"Created pipes with permissions 666")
            
        except Exception as e:
            print(f"Error creating pipes: {e}")
    
    def get_session_id(self):
        """컨테이너 이름에서 세션 ID 추출"""
        hostname = os.environ.get('HOSTNAME', socket.gethostname())
        if hostname.startswith('infotainment_'):
            return hostname[13:]
        return hostname
    
    def connect_to_broker(self):
        """CAN 브로커에 연결"""
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect(('gateway_shared', 9999))
                
                # 핸드셰이크
                handshake = {
                    'session_id': self.session_id,
                    'type': 'infotainment'
                }
                self.sock.send(json.dumps(handshake).encode())
                
                # 응답 대기
                response = self.sock.recv(1024).decode().strip()
                resp_data = json.loads(response)
                
                if resp_data['status'] == 'connected':
                    print(f"CAN daemon connected: {self.session_id}")
                    return True
                    
            except Exception as e:
                print(f"Connection failed, retrying: {e}")
                time.sleep(2)
    
    def broker_sender(self):
        """브로커로 메시지 전송 스레드"""
        while self.running:
            try:
                # 큐에서 메시지 가져오기
                msg_data = self.send_queue.get(timeout=1)
                
                # 송신 메시지를 candump에도 표시
                formatted_tx = f"({msg_data['timestamp']:.6f}) vcan0 {msg_data['can_id']:03X}#{msg_data['data'].upper()}"
                self.display_message(formatted_tx)
                
                # 브로커로 전송
                self.sock.send((json.dumps(msg_data) + '\n').encode())
                print(f"Sent: ID=0x{msg_data['can_id']:03X}, Data={msg_data['data']}")
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Send error: {e}")
                break
    
    def broker_receiver(self):
        """브로커에서 메시지 수신 스레드"""
        buffer = ""
        while self.running:
            try:
                data = self.sock.recv(1024).decode()
                if not data:
                    break
                
                buffer += data
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    if line.strip():
                        msg_data = json.loads(line.strip())
                        
                        if msg_data['type'] == 'receive':
                            # 수신된 메시지를 candump으로 표시
                            formatted_rx = f"({msg_data['timestamp']:.6f}) vcan0 {msg_data['can_id']:03X}#{msg_data['data'].upper()}"
                            self.display_message(formatted_rx)
                            print(f"Received: ID=0x{msg_data['can_id']:03X}, Data={msg_data['data']}")
                        
            except Exception as e:
                print(f"Receive error: {e}")
                break
    
    def display_message(self, formatted_message):
        """candump에 메시지 표시"""
        # 로그 파일에 먼저 쓰기 (항상 성공)
        try:
            log_file = "/tmp/can_daemon/messages.log"
            with open(log_file, 'a') as log:
                log.write(formatted_message + '\n')
                log.flush()
        except:
            pass
        
        # 파이프에 쓰기 시도 (non-blocking, reader가 없어도 블록되지 않음)
        try:
            import fcntl
            fd = os.open(self.recv_pipe, os.O_WRONLY | os.O_NONBLOCK)
            os.write(fd, (formatted_message + '\n').encode())
            os.close(fd)
        except:
            # Reader가 없거나 파이프가 full이면 조용히 무시
            pass
    
    def pipe_handler(self):
        """로컬 파이프 처리 스레드"""
        while self.running:
            try:
                # cansend에서 오는 메시지 처리
                with open(self.send_pipe, 'r') as pipe:
                    for line in pipe:
                        try:
                            msg_data = json.loads(line.strip())
                            self.send_queue.put(msg_data)
                        except:
                            pass
                            
            except Exception as e:
                time.sleep(0.1)
    
    def candump_server(self):
        """candump을 위한 메시지 서버 (이제 불필요)"""
        # display_message 함수로 통합되었으므로 빈 함수
        while self.running:
            time.sleep(1)
    
    def start(self):
        """데몬 시작"""
        print(f"Starting CAN daemon for session: {self.session_id}")
        
        # 브로커 연결
        if not self.connect_to_broker():
            return False
        
        self.running = True
        
        # 워커 스레드들 시작
        threads = [
            threading.Thread(target=self.broker_sender, daemon=True),
            threading.Thread(target=self.broker_receiver, daemon=True),
            threading.Thread(target=self.pipe_handler, daemon=True),
            threading.Thread(target=self.candump_server, daemon=True)
        ]
        
        for t in threads:
            t.start()
        
        # 메인 루프
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down CAN daemon...")
            self.running = False
            self.sock.close()

if __name__ == "__main__":
    daemon = CANDaemon()
    daemon.start()