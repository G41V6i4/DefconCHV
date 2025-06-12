#!/usr/bin/env python3
import socket
import threading
import struct
import subprocess
import time
import os
import sys
import signal

class DockerCanBridge:
    """
    Docker 컨테이너 환경에 최적화된 CAN 브릿지
    인포테인먼트 <-> 엔진 ECU 간 CAN 통신을 중개
    """
    
    def __init__(self):
        self.bridges = {}             # {interface_pair: bridge_data}
        self.running = True
        self.interfaces = {
            'infotainment': os.environ.get('INFOTAINMENT_CAN', 'vcan0'),
            'engine': os.environ.get('ENGINE_CAN', 'vcan1')
        }
        self.session_prefix = os.environ.get('SESSION_PREFIX', 'vcan')
        signal.signal(signal.SIGTERM, self.handle_signal)
        signal.signal(signal.SIGINT, self.handle_signal)
        
    def handle_signal(self, signum, frame):
        """Docker에서 종료 시그널 처리"""
        print(f"[!] Received signal {signum}, shutting down...")
        self.running = False
    
    def setup_vcan_interfaces(self):
        """필요한 기본 vcan 인터페이스 설정"""
        interfaces = [self.interfaces['infotainment'], self.interfaces['engine']]
        
        for iface in interfaces:
            try:
                # 인터페이스가 존재하는지 확인
                result = subprocess.run(['ip', 'link', 'show', iface], 
                                      capture_output=True, text=True)
                
                if result.returncode != 0:
                    print(f"[*] Creating interface: {iface}")
                    # vcan 커널 모듈 로드
                    subprocess.run(['modprobe', 'vcan'], check=True)
                    # 인터페이스 생성
                    subprocess.run(['ip', 'link', 'add', 'dev', iface, 'type', 'vcan'], check=True)
                    # 인터페이스 활성화
                    subprocess.run(['ip', 'link', 'set', 'up', iface], check=True)
                    print(f"[+] Successfully created {iface}")
            except Exception as e:
                print(f"[!] Error setting up {iface}: {e}")
                if "Operation not permitted" in str(e):
                    print("[!] Need privileged mode for CAN interface creation")
    
    def create_bridge(self, interface1, interface2):
        """두 CAN 인터페이스 간 브리지 생성"""
        bridge_key = f"{interface1}_{interface2}"
        if bridge_key in self.bridges:
            print(f"[!] Bridge {bridge_key} already exists")
            return False
        
        try:
            # 소켓 생성
            sock1 = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            sock1.bind((interface1,))
            
            sock2 = socket.socket(socket.AF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
            sock2.bind((interface2,))
            
            print(f"[+] Bridge created: {interface1} <-> {interface2}")
            
            # 양방향 전달 함수
            def forward(src_sock, dst_sock, src_name, dst_name):
                while self.running and bridge_key in self.bridges:
                    try:
                        frame = src_sock.recv(16)
                        can_id, length = struct.unpack("=IB", frame[:5])
                        data = frame[8:8+length]
                        
                        # 전달
                        dst_sock.send(frame)
                        
                        # 로그 (hex 형식으로 출력)
                        timestamp = time.strftime("%H:%M:%S")
                        print(f"[{timestamp}] {src_name} -> {dst_name}: "
                              f"ID=0x{can_id:03X}, Data={data.hex()}")
                              
                    except Exception as e:
                        if self.running and bridge_key in self.bridges:
                            print(f"[!] Bridge error {src_name}->{dst_name}: {e}")
                        break
            
            # 전달 스레드 시작
            thread1 = threading.Thread(
                target=forward,
                args=(sock1, sock2, interface1, interface2),
                daemon=True
            )
            thread2 = threading.Thread(
                target=forward,
                args=(sock2, sock1, interface2, interface1),
                daemon=True
            )
            
            thread1.start()
            thread2.start()
            
            # 브리지 정보 저장
            self.bridges[bridge_key] = {
                'threads': [thread1, thread2],
                'sockets': [sock1, sock2],
                'interfaces': (interface1, interface2),
                'created_at': time.time()
            }
            
            return True
            
        except Exception as e:
            print(f"[!] Failed to create bridge between {interface1} and {interface2}: {e}")
            return False
    
    def remove_bridge(self, bridge_key):
        """브리지 제거"""
        if bridge_key in self.bridges:
            bridge_info = self.bridges[bridge_key]
            
            # 소켓 닫기
            for sock in bridge_info['sockets']:
                try:
                    sock.close()
                except:
                    pass
            
            del self.bridges[bridge_key]
            print(f"[-] Bridge removed: {bridge_key}")
    
    def monitor_interfaces(self):
        """새로운 vcan 인터페이스 감지 및 자동 브리지 생성"""
        infotainment_iface = self.interfaces['infotainment']
        engine_iface = self.interfaces['engine']
        known_interfaces = set([infotainment_iface, engine_iface])
        
        while self.running:
            try:
                # 현재 vcan 인터페이스 목록 가져오기
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True)
                
                current_interfaces = set()
                for line in result.stdout.split('\n'):
                    if self.session_prefix in line and ':' in line:
                        # 인터페이스 이름 추출
                        parts = line.split(':')
                        if len(parts) >= 2:
                            iface_name = parts[1].strip()
                            if iface_name.startswith(self.session_prefix):
                                current_interfaces.add(iface_name)
                
                # 새로운 세션 인터페이스 감지
                for iface in current_interfaces:
                    if iface not in known_interfaces and iface != infotainment_iface and iface != engine_iface:
                        print(f"[*] New interface detected: {iface}")
                        # 인포테인먼트와 브릿지 생성
                        self.create_bridge(iface, infotainment_iface)
                        # 엔진과 브릿지 생성
                        self.create_bridge(iface, engine_iface)
                        known_interfaces.add(iface)
                
                # 제거된 인터페이스 감지 및 브릿지 제거
                removed_interfaces = known_interfaces - current_interfaces
                for iface in removed_interfaces:
                    if iface != infotainment_iface and iface != engine_iface:
                        print(f"[*] Interface removed: {iface}")
                        # 관련 브릿지 찾아서 제거
                        bridges_to_remove = []
                        for bridge_key in self.bridges:
                            if iface in bridge_key:
                                bridges_to_remove.append(bridge_key)
                        
                        for bridge_key in bridges_to_remove:
                            self.remove_bridge(bridge_key)
                        
                        known_interfaces.discard(iface)
                
            except Exception as e:
                print(f"[!] Monitor error: {e}")
            
            time.sleep(1)  # 1초마다 확인
    
    def start(self):
        """브릿지 시작"""
        print("[+] Docker CAN Bridge starting...")
        
        # 기본 인터페이스 설정
        self.setup_vcan_interfaces()
        
        # 기본 브릿지 설정 (인포테인먼트 <-> 엔진)
        self.create_bridge(self.interfaces['infotainment'], self.interfaces['engine'])
        
        print("[+] Monitoring for new vcan interfaces...")
        
        # 모니터링 스레드 시작
        monitor_thread = threading.Thread(target=self.monitor_interfaces, daemon=True)
        monitor_thread.start()
        
        try:
            # 메인 스레드는 종료 신호를 대기
            while self.running:
                time.sleep(0.1)
        except KeyboardInterrupt:
            print("\n[!] Shutting down...")
            self.running = False
        
        # 모든 브리지 정리
        for bridge_key in list(self.bridges.keys()):
            self.remove_bridge(bridge_key)
        
        print("[-] Bridge stopped")


if __name__ == "__main__":
    # 환경 변수로 구성을 제어할 수 있음
    bridge = DockerCanBridge()
    bridge.start()
