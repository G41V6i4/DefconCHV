#!/bin/bash
# ECU 시뮬레이터 Docker 환경 구성 스크립트

set -e

echo "=== ECU Simulator Docker Setup ==="

# 작업 디렉토리 생성
mkdir -p ecu_simulator/{infotainment,gateway,engine}
cd ecu_simulator

# 1. 인포테인먼트 ECU Dockerfile
cat > infotainment/Dockerfile << 'EOF'
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    kmod \
    net-tools \
    netcat \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Custom CAN tools 설치
COPY cansend /usr/local/bin/cansend
COPY candump /usr/local/bin/candump
RUN chmod +x /usr/local/bin/cansend /usr/local/bin/candump

# 취약한 펌웨어 및 디버그 인터페이스
COPY firmware/ /opt/firmware/
COPY debug_interface.py /opt/debug_interface.py

# SSH 서비스는 제거하고 간단한 TCP 서비스로 대체
COPY infotainment_service.py /opt/infotainment_service.py

WORKDIR /opt
EXPOSE 1234

CMD ["python3", "infotainment_service.py"]
EOF

# 2. 게이트웨이 ECU Dockerfile  
cat > gateway/Dockerfile << 'EOF'
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    kmod \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# CAN Broker 설치
COPY can_broker.py /opt/can_broker.py
COPY gateway_ecu.py /opt/gateway_ecu.py

# Custom CAN tools
COPY cansend /usr/local/bin/cansend
COPY candump /usr/local/bin/candump
RUN chmod +x /usr/local/bin/cansend /usr/local/bin/candump

WORKDIR /opt

# CAN Broker와 Gateway ECU를 병렬로 실행
CMD python3 can_broker.py & python3 gateway_ecu.py && wait
EOF

# 3. 엔진 ECU Dockerfile
cat > engine/Dockerfile << 'EOF'
FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    kmod \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Custom CAN tools
COPY cansend /usr/local/bin/cansend  
COPY candump /usr/local/bin/candump
RUN chmod +x /usr/local/bin/cansend /usr/local/bin/candump

COPY engine_ecu.py /opt/engine_ecu.py

WORKDIR /opt
CMD ["python3", "engine_ecu.py"]
EOF

# 4. 인포테인먼트 서비스 (취약점 포함)
cat > infotainment/infotainment_service.py << 'EOF'
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
EOF

# 5. 게이트웨이 ECU 서비스
cat > gateway/gateway_ecu.py << 'EOF'
#!/usr/bin/env python3
"""
게이트웨이 ECU - 인증 및 메시지 필터링
"""
import time
import threading
import struct

class GatewayECU:
    def __init__(self):
        self.authenticated_sessions = {}
        
    def start(self):
        print("Gateway ECU started")
        # 실제로는 CAN 브로커가 인증 로직을 처리
        # 이 서비스는 추가적인 게이트웨이 기능을 담당
        
        while True:
            time.sleep(1)
            self.cleanup_expired_sessions()
    
    def cleanup_expired_sessions(self):
        """만료된 세션 정리"""
        current_time = time.time()
        expired = []
        
        for session_id, auth_time in self.authenticated_sessions.items():
            if current_time - auth_time > 300:  # 5분 타임아웃
                expired.append(session_id)
        
        for session_id in expired:
            del self.authenticated_sessions[session_id]
            print(f"Session {session_id} expired")

if __name__ == "__main__":
    gateway = GatewayECU()
    gateway.start()
EOF

# 6. 엔진 ECU 서비스
cat > engine/engine_ecu.py << 'EOF'
#!/usr/bin/env python3
"""
엔진 ECU - 최종 목표 플래그 보관
"""
import socket
import json
import time
import threading
import struct

class EngineECU:
    def __init__(self):
        self.secret_flag = "CTF{ECU_HACKING_COMPLETE_2024}"
        self.diagnostic_mode = False
        
    def start(self):
        print("Engine ECU started")
        
        # CAN 브로커에 연결
        while True:
            try:
                self.connect_to_broker()
                break
            except:
                print("Waiting for CAN broker...")
                time.sleep(2)
    
    def connect_to_broker(self):
        """CAN 브로커에 연결"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 9999))
        
        # 핸드셰이크
        handshake = {
            'session_id': 'engine_shared',
            'type': 'engine'
        }
        sock.send(json.dumps(handshake).encode())
        
        # 응답 대기
        response = sock.recv(1024).decode().strip()
        print(f"Connected to CAN broker: {response}")
        
        # 메시지 수신 루프
        buffer = ""
        while True:
            data = sock.recv(1024).decode()
            if not data:
                break
            
            buffer += data
            while '\n' in buffer:
                line, buffer = buffer.split('\n', 1)
                if line.strip():
                    self.process_can_message(line.strip(), sock)
    
    def process_can_message(self, message, sock):
        """CAN 메시지 처리"""
        try:
            msg_data = json.loads(message)
            
            if msg_data['type'] == 'forward':
                # 게이트웨이를 통해 전달된 메시지
                original_session = msg_data['original_session']
                can_id = msg_data['can_id']
                data = bytes.fromhex(msg_data['data'])
                
                response = self.handle_engine_command(can_id, data)
                if response:
                    # 응답을 원본 세션으로 전송
                    response_msg = {
                        'type': 'engine_response',
                        'target_session': original_session,
                        'can_id': response['can_id'],
                        'data': response['data'].hex(),
                        'timestamp': time.time()
                    }
                    sock.send((json.dumps(response_msg) + '\n').encode())
                    
        except Exception as e:
            print(f"Error processing message: {e}")
    
    def handle_engine_command(self, can_id, data):
        """엔진 명령어 처리"""
        if can_id == 0x7E0:  # UDS 진단 요청
            return self.handle_uds_request(data)
        elif can_id == 0x456:  # 일반 엔진 제어
            return self.handle_engine_control(data)
        
        return None
    
    def handle_uds_request(self, data):
        """UDS (Unified Diagnostic Services) 요청 처리"""
        if len(data) < 1:
            return None
        
        service_id = data[0]
        
        if service_id == 0x10:  # Diagnostic Session Control
            if len(data) >= 2 and data[1] == 0x03:  # Extended Diagnostic Session
                self.diagnostic_mode = True
                return {
                    'can_id': 0x7E8,  # UDS 응답
                    'data': bytes([0x50, 0x03])  # Positive response
                }
        
        elif service_id == 0x27 and self.diagnostic_mode:  # Security Access
            if len(data) >= 2:
                if data[1] == 0x01:  # Request Seed
                    seed = struct.pack('>H', 0x1337)  # 고정 시드 (취약점)
                    return {
                        'can_id': 0x7E8,
                        'data': bytes([0x67, 0x01]) + seed
                    }
                elif data[1] == 0x02 and len(data) >= 4:  # Send Key
                    key = struct.unpack('>H', data[2:4])[0]
                    if key == 0x1337 ^ 0xCAFE:  # 간단한 키 검증
                        return {
                            'can_id': 0x7E8,
                            'data': bytes([0x67, 0x02])  # Security unlocked
                        }
        
        elif service_id == 0x22 and self.diagnostic_mode:  # Read Data by Identifier
            if len(data) >= 3:
                did = struct.unpack('>H', data[1:3])[0]
                if did == 0xF190:  # Vehicle Identification Number
                    return {
                        'can_id': 0x7E8,
                        'data': bytes([0x62, 0xF1, 0x90]) + self.secret_flag.encode()[:5]
                    }
                elif did == 0xF1A0:  # Secret Flag DID
                    return {
                        'can_id': 0x7E8,
                        'data': bytes([0x62, 0xF1, 0xA0]) + self.secret_flag.encode()
                    }
        
        # 기본 부정응답
        return {
            'can_id': 0x7E8,
            'data': bytes([0x7F, service_id, 0x11])  # Service not supported
        }
    
    def handle_engine_control(self, data):
        """일반 엔진 제어 명령"""
        # 간단한 엔진 상태 응답
        return {
            'can_id': 0x4A0,
            'data': bytes([0x01, 0x23, 0x45, 0x67])  # 엔진 상태 데이터
        }

if __name__ == "__main__":
    engine = EngineECU()
    engine.start()
EOF

# 7. 빌드 및 배포 스크립트
cat > build_and_deploy.sh << 'EOF'
#!/bin/bash

echo "Building ECU simulator images..."

# Custom CAN tools를 각 디렉토리에 복사
cp ../can_broker.py gateway/
cp ../cansend.py infotainment/cansend
cp ../candump.py infotainment/candump
cp ../cansend.py gateway/cansend  
cp ../candump.py gateway/candump
cp ../cansend.py engine/cansend
cp ../candump.py engine/candump

# 펌웨어 디렉토리 생성 (1단계용)
mkdir -p infotainment/firmware
echo "FIRMWARE_BINARY_DATA_WITH_HIDDEN_DEBUG_STRINGS" > infotainment/firmware/infotainment.bin

# Docker 이미지 빌드
docker build -t ecu_infotainment:latest infotainment/
docker build -t ecu_gateway:latest gateway/
docker build -t ecu_engine:latest engine/

echo "ECU simulator images built successfully!"
echo "Use the main Flask application to start individual sessions."
EOF

chmod +x build_and_deploy.sh

# 8. 통합 Docker Compose (테스트용)
cat > docker-compose.test.yml << 'EOF'
version: '3.8'

services:
  gateway:
    image: ecu_gateway:latest
    container_name: gateway_shared
    networks:
      - ecu_network
    restart: unless-stopped
    
  engine:
    image: ecu_engine:latest
    container_name: engine_shared
    networks:
      - ecu_network
    restart: unless-stopped
    depends_on:
      - gateway
      
  infotainment_test:
    image: ecu_infotainment:latest
    container_name: infotainment_test
    networks:
      - ecu_network
    ports:
      - "12340:1234"
    depends_on:
      - gateway

networks:
  ecu_network:
    driver: bridge
EOF

# 9. 사용법 안내
cat > README.md << 'EOF'
# ECU Simulator Setup

## 빌드 및 배포

1. 먼저 custom CAN tools를 생성:
```bash
# Python 스크립트들을 실행 가능하게 만들기
chmod +x cansend.py candump.py can_broker.py
```

2. Docker 이미지 빌드:
```bash
./build_and_deploy.sh
```

3. 테스트 환경 실행:
```bash
docker-compose -f docker-compose.test.yml up -d
```

## 사용법

### 1단계: 펌웨어 분석
```bash
# 펌웨어 다운로드 후 문자열 추출
strings infotainment.bin | grep debug
```

### 2단계: 인포테인먼트 접근
```bash
# 인포테인먼트 시스템 접근
nc localhost 12340
> debug_enable_dev_mode
> dev_shell
```

### 3단계: CAN 네트워크 분석  
```bash
# 컨테이너 내부에서
candump vcan0 &
cansend vcan0 123#1234567890ABCDEF
```

### 4단계: 게이트웨이 인증
```bash
# 시드-키 인증
cansend vcan0 123#DEADBEEF12345678
```

### 5단계: 엔진 ECU 접근
```bash
# UDS 진단 세션 시작
cansend vcan0 7E0#1003

# 보안 접근
cansend vcan0 7E0#2701
cansend vcan0 7E0#2702CAFE

# 플래그 읽기
cansend vcan0 7E0#22F1A0
```
EOF

echo "=== Setup Complete ==="
echo "1. Run: ./build_and_deploy.sh"
echo "2. Test with: docker-compose -f docker-compose.test.yml up -d"
echo "3. Connect to: nc localhost 12340"
