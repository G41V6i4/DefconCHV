#!/usr/bin/env python3

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
        
        self.pipe_dir = "/tmp/can_daemon"
        Path(self.pipe_dir).mkdir(exist_ok=True)
        self.send_pipe = f"{self.pipe_dir}/send"
        self.recv_pipe = f"{self.pipe_dir}/recv"
        self.log_file = f"{self.pipe_dir}/messages.log"
        
        self.create_pipes()
        self.create_log_file()
    
    def create_log_file(self):
        try:
            with open(self.log_file, 'a') as log:
                log.write(f"CAN daemon started at {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                log.flush()
            print(f"Log file initialized: {self.log_file}")
        except Exception as e:
            print(f"Error creating log file: {e}")
    
    def create_pipes(self):
        try:
            for pipe in [self.send_pipe, self.recv_pipe]:
                if os.path.exists(pipe):
                    os.unlink(pipe)
            
            os.mkfifo(self.send_pipe, 0o666)
            os.mkfifo(self.recv_pipe, 0o666)
            
            os.chmod(self.send_pipe, 0o666)
            os.chmod(self.recv_pipe, 0o666)
            
            print(f"Created pipes with permissions 666")
            
        except Exception as e:
            print(f"Error creating pipes: {e}")
    
    def get_session_id(self):
        hostname = os.environ.get('HOSTNAME', socket.gethostname())
        if hostname.startswith('infotainment_'):
            return hostname[13:]
        return hostname
    
    def connect_to_broker(self):
        while True:
            try:
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.sock.connect(('gateway_shared', 9999))
                
                handshake = {
                    'session_id': self.session_id,
                    'type': 'infotainment'
                }
                self.sock.send(json.dumps(handshake).encode())
                
                response = self.sock.recv(1024).decode().strip()
                resp_data = json.loads(response)
                
                if resp_data['status'] == 'connected':
                    print(f"CAN daemon connected: {self.session_id}")
                    return True
                    
            except Exception as e:
                print(f"Connection failed, retrying: {e}")
                time.sleep(2)
    
    def broker_sender(self):
        while self.running:
            try:
                msg_data = self.send_queue.get(timeout=1)
                
                formatted_tx = f"({msg_data['timestamp']:.6f}) vcan0 {msg_data['can_id']:03X}#{msg_data['data'].upper()}"
                self.display_message(formatted_tx)
                
                self.sock.send((json.dumps(msg_data) + '\n').encode())
                print(f"Sent: ID=0x{msg_data['can_id']:03X}, Data={msg_data['data']}")
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"Send error: {e}")
                break
    
    def broker_receiver(self):
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
                            formatted_rx = f"({msg_data['timestamp']:.6f}) vcan0 {msg_data['can_id']:03X}#{msg_data['data'].upper()}"
                            self.display_message(formatted_rx)
                            print(f"Received: ID=0x{msg_data['can_id']:03X}, Data={msg_data['data']}")
                        
            except Exception as e:
                print(f"Receive error: {e}")
                break
    
    def display_message(self, formatted_message):
        try:
            with open(self.log_file, 'a') as log:
                log.write(formatted_message + '\n')
                log.flush()
        except:
            pass
        
        try:
            import fcntl
            fd = os.open(self.recv_pipe, os.O_WRONLY | os.O_NONBLOCK)
            os.write(fd, (formatted_message + '\n').encode())
            os.close(fd)
        except:
            pass
    
    def pipe_handler(self):
        while self.running:
            try:
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
        while self.running:
            time.sleep(1)
    
    def start(self):
        print(f"Starting CAN daemon for session: {self.session_id}")
        
        if not self.connect_to_broker():
            return False
        
        self.running = True
        
        threads = [
            threading.Thread(target=self.broker_sender, daemon=True),
            threading.Thread(target=self.broker_receiver, daemon=True),
            threading.Thread(target=self.pipe_handler, daemon=True),
            threading.Thread(target=self.candump_server, daemon=True)
        ]
        
        for t in threads:
            t.start()
        
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