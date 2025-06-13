#!/usr/bin/env python3
"""
인포테인먼트 ECU 서비스 - 취약점을 포함한 디버그 인터페이스
"""
import socket
import subprocess
import threading
import os

class InfotainmentService:
    def __init__(self, port=1234):
        self.port = port
        self.debug_mode = False
        
    def start(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', self.port))
        server.listen(5)
        
        print(f"Infotainment service started on port {self.port}")
        
        while True:
            client, addr = server.accept()
            thread = threading.Thread(target=self.handle_client, args=(client,))
            thread.start()
    
    def handle_client(self, client):
        try:
            client.send(b"Infotainment System v1.2.3\n")
            client.send(b"Type 'help' for commands\n> ")
            
            while True:
                data = client.recv(1024).decode().strip()
                if not data:
                    break
                
                response = self.process_command(data)
                client.send(response.encode() + b"\n> ")
                
        except Exception as e:
            print(f"Client error: {e}")
        finally:
            client.close()
    
    def process_command(self, cmd):
        """명령어 처리 - 취약점 포함"""
        cmd = cmd.strip()
        
        if cmd == "help":
            return "Available commands: status, version, debug, exit"
        
        elif cmd == "status":
            return "System Status: OK"
        
        elif cmd == "version":
            return "Infotainment OS v1.2.3 (Build 20241201)"
        
        elif cmd == "debug":
            return "Debug mode access denied. Contact manufacturer."
        
        elif cmd.startswith("debug_"):
            # 히든 디버그 명령어 (리버스 엔지니어링으로 발견해야 함)
            if cmd == "debug_enable_dev_mode":
                self.debug_mode = True
                return "Developer mode enabled. Use 'dev_help' for commands."
            else:
                return "Unknown debug command"
        
        elif cmd == "dev_help" and self.debug_mode:
            return "Dev commands: dev_shell, dev_info, dev_firmware_update"
        
        elif cmd == "dev_shell" and self.debug_mode:
            # 버퍼 오버플로우 취약점
            return "Shell access: " + "A" * 1000  # 의도적 취약점
        
        elif cmd.startswith("dev_firmware_update ") and self.debug_mode:
            # 명령 인젝션 취약점
            filename = cmd[20:]  # 입력 검증 없음
            try:
                # 실제로는 위험하지만 샌드박스 환경에서는 안전
                result = subprocess.check_output(f"ls -la {filename}", shell=True, stderr=subprocess.STDOUT)
                return result.decode()
            except:
                return "Firmware update failed"
        
        elif cmd == "exit":
            return "Goodbye"
        
        else:
            return "Unknown command. Type 'help' for available commands."

if __name__ == "__main__":
    service = InfotainmentService()
    service.start()
