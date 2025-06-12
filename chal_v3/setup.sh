#!/bin/bash

# Automotive CTF Master Setup Script
# Run this on a fresh Ubuntu 20.04+ system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Print colored messages
print_success() { echo -e "${GREEN}[+]${NC} $1"; }
print_error() { echo -e "${RED}[-]${NC} $1"; }
print_info() { echo -e "${BLUE}[*]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then 
        print_warning "Running as root. This may cause permission issues."
        print_info "Creating non-root user for CTF..."
        useradd -m -s /bin/bash ctfuser || true
        usermod -aG sudo ctfuser || true
    fi
}



# Create CTF directory structure
create_directory_structure() {
    print_info "Creating CTF directory structure..."
    
    # Main directories
    mkdir -p automotive_ctf/{gateway_ecu,infotainment_ecu,engine_ecu}
    mkdir -p automotive_ctf/{exploits,tools,scripts,setup}
    mkdir -p automotive_ctf/{challenges,docs,tests,logs,config,writeups}
    mkdir -p automotive_ctf/logs/{gateway,infotainment,engine,exploits}
    
    # Sub-directories
    mkdir -p automotive_ctf/infotainment_ecu/media/{songs,config,system}
    mkdir -p automotive_ctf/exploits/payloads
    mkdir -p automotive_ctf/tools/monitoring
    mkdir -p automotive_ctf/gateway_ecu/config
    
    # Challenge levels
    for i in {1..5}; do
        mkdir -p automotive_ctf/challenges/level$i
    done
    
    cd automotive_ctf
    
    print_success "Directory structure created"
}

# Create all necessary files
create_all_files() {
    print_info "Creating all CTF files..."
    
    # Gateway ECU Files
    cat > gateway_ecu/Dockerfile << 'EOF'
FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    net-tools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway_sim.py .
COPY auth_protocol.py .
COPY routing_rules.json .

RUN mkdir -p /var/log/gateway

ENV CAN_INTERFACE=vcan0
ENV PYTHONUNBUFFERED=1

EXPOSE 8080 8081

CMD ["python", "gateway_sim.py"]
EOF

    cat > gateway_ecu/requirements.txt << 'EOF'
python-can==4.2.2
websockets==11.0.3
aiohttp==3.8.5
pyyaml==6.0
cryptography==41.0.4
EOF

    cat > gateway_ecu/gateway_sim.py << 'EOF'
import asyncio
import websockets
import can
import json
import logging
import time
import struct
from collections import defaultdict
from auth_protocol import AuthProtocol
import threading
import os

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class CANGateway:
    def __init__(self):
        self.can_interface = os.environ.get('CAN_INTERFACE', 'vcan0')
        self.clients = {}
        self.client_sessions = defaultdict(dict)
        self.auth_protocol = AuthProtocol()
        self.bus = None
        self.running = False
        
        with open('routing_rules.json') as f:
            self.routing_rules = json.load(f)
            
    async def handle_client(self, websocket, path):
        client_id = id(websocket)
        client_ip = websocket.remote_address[0]
        
        logger.info(f"New client connected: {client_ip}")
        self.clients[client_id] = {
            'websocket': websocket,
            'authenticated': False,
            'session_id': None,
            'ip': client_ip
        }
        
        try:
            await websocket.send(json.dumps({
                'type': 'welcome',
                'message': 'Connected to CAN Gateway. Please authenticate.',
                'challenge': self.auth_protocol.generate_challenge()
            }))
            
            async for message in websocket:
                await self.process_client_message(client_id, message)
                
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        finally:
            await self.cleanup_client(client_id)
            
    async def process_client_message(self, client_id, message):
        try:
            data = json.loads(message)
            client = self.clients[client_id]
            
            if data['type'] == 'auth':
                if self.auth_protocol.verify_response(data['response'], data.get('challenge')):
                    client['authenticated'] = True
                    client['session_id'] = self.generate_session_id()
                    
                    await client['websocket'].send(json.dumps({
                        'type': 'auth_success',
                        'session_id': client['session_id']
                    }))
                else:
                    await client['websocket'].send(json.dumps({
                        'type': 'auth_failed'
                    }))
                    
            elif data['type'] == 'can_send' and client['authenticated']:
                can_id = data['can_id']
                can_data = data['data']
                
                session_bytes = struct.pack('>H', client['session_id'])
                modified_data = session_bytes + bytes(can_data)[:6]
                
                msg = can.Message(
                    arbitration_id=can_id,
                    data=modified_data,
                    is_extended_id=data.get('is_extended', False)
                )
                
                self.bus.send(msg)
                
        except Exception as e:
            logger.error(f"Error processing message: {e}")
            
    def generate_session_id(self):
        return int(time.time() * 1000) & 0xFFFF
        
    async def start(self):
        self.bus = can.interface.Bus(self.can_interface, bustype='socketcan')
        self.running = True
        
        server = await websockets.serve(self.handle_client, '0.0.0.0', 8080)
        logger.info("CAN Gateway started on port 8080")
        
        await asyncio.Future()

if __name__ == "__main__":
    gateway = CANGateway()
    asyncio.run(gateway.start())
EOF

    cat > gateway_ecu/auth_protocol.py << 'EOF'
import hmac
import hashlib
import time
import secrets

class AuthProtocol:
    def __init__(self):
        self.secret_key = b"CTF_CAN_GATEWAY_SECRET_2024"
        self.challenges = {}
        
    def generate_challenge(self):
        challenge = secrets.token_hex(16)
        self.challenges[challenge] = time.time()
        return challenge
        
    def verify_response(self, response, challenge):
        if challenge not in self.challenges:
            return False
            
        expected = hmac.new(
            self.secret_key,
            challenge.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(response, expected)
EOF

    cat > gateway_ecu/routing_rules.json << 'EOF'
{
    "allowed_ranges": {
        "infotainment": ["0x300-0x3FF"],
        "engine": ["0x700-0x7FF"]
    },
    "restricted_ids": ["0x7E0", "0x7DF"],
    "rate_limits": {
        "global": 1000,
        "per_client": 100
    }
}
EOF

    # Infotainment ECU Files
    cat > infotainment_ecu/Dockerfile << 'EOF'
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    can-utils \
    iproute2 \
    gdb \
    net-tools \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY infotainment_simulator.c .
COPY Makefile .
COPY infotainment.conf .

RUN mkdir -p /app/media/songs /app/media/config
RUN echo "Admin password: Sup3rS3cr3t!" > /app/media/config/admin.txt

RUN make vulnerable

RUN echo "FLAG{1nf0t41nm3nt_pwn3d_$(openssl rand -hex 8)}" > /flag.txt
RUN chmod 644 /flag.txt

ENV CAN_INTERFACE=vcan0

EXPOSE 8888 9999

CMD ["./infotainment_simulator"]
EOF

    cat > infotainment_ecu/Makefile << 'EOF'
CC = gcc
CFLAGS = -Wall -g -fno-stack-protector -z execstack
LDFLAGS = -pthread

TARGET = infotainment_simulator

all: $(TARGET)

$(TARGET): infotainment_simulator.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

vulnerable: CFLAGS += -fno-stack-protector -z execstack -D_FORTIFY_SOURCE=0 -no-pie
vulnerable: clean $(TARGET)

clean:
	rm -f $(TARGET)

.PHONY: all clean vulnerable
EOF

    cat > infotainment_ecu/infotainment_simulator.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/can.h>
#include <linux/can/raw.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>

#define CAN_INTERFACE "vcan0"
#define WEB_PORT 8888

int running = 1;
int can_socket;
int web_server_socket;

void spawn_shell() {
    system("/bin/sh");
}

void handle_http_request(int client_socket) {
    char buffer[1024] = {0};
    char response[4096] = {0};
    char method[16], path[256], version[16];
    
    recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    sscanf(buffer, "%s %s %s", method, path, version);
    
    if (strstr(path, "/play?file=")) {
        char *filename = strstr(path, "file=") + 5;
        char command[256];
        sprintf(command, "mplayer %s", filename);
        system(command);
        
        sprintf(response, "HTTP/1.1 200 OK\r\n\r\nPlaying: %s", filename);
    }
    else if (strstr(path, "/files/")) {
        char filepath[512];
        sprintf(filepath, "./media%s", path + 6);
        
        FILE *file = fopen(filepath, "r");
        if (file) {
            char file_content[2048];
            fread(file_content, 1, sizeof(file_content) - 1, file);
            fclose(file);
            sprintf(response, "HTTP/1.1 200 OK\r\n\r\n%s", file_content);
        }
    }
    else {
        sprintf(response, "HTTP/1.1 200 OK\r\n\r\n<h1>Infotainment System</h1>");
    }
    
    send(client_socket, response, strlen(response), 0);
    close(client_socket);
}

void *web_server_thread(void *arg) {
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    
    web_server_socket = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(WEB_PORT);
    
    bind(web_server_socket, (struct sockaddr *)&address, sizeof(address));
    listen(web_server_socket, 3);
    
    while (running) {
        int client_socket = accept(web_server_socket, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (client_socket >= 0) {
            handle_http_request(client_socket);
        }
    }
    return NULL;
}

int main() {
    printf("Infotainment ECU starting...\n");
    printf("Hidden functions: spawn_shell @ %p\n", spawn_shell);
    
    pthread_t web_thread;
    pthread_create(&web_thread, NULL, web_server_thread, NULL);
    
    while (running) {
        sleep(1);
    }
    
    return 0;
}
EOF

    cat > infotainment_ecu/infotainment.conf << 'EOF'
admin_password = default123
media_path = /app/media
web_port = 8888
EOF

    # Engine ECU Files
    cat > engine_ecu/Dockerfile << 'EOF'
FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine_simulator_secure.py .
COPY uds_service.py .
COPY secret.txt .

ENV CAN_INTERFACE=vcan0

CMD ["python", "engine_simulator_secure.py"]
EOF

    cat > engine_ecu/requirements.txt << 'EOF'
python-can==4.2.2
cryptography==41.0.4
EOF

    cat > engine_ecu/engine_simulator_secure.py << 'EOF'
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
        self.can_interface = os.environ.get('CAN_INTERFACE', 'vcan0')
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
EOF

    cat > engine_ecu/uds_service.py << 'EOF'
class UDSService:
    def __init__(self, ecu):
        self.ecu = ecu
        
    def process_request(self, data):
        # Basic UDS implementation
        return bytes([0x7F, data[0], 0x11])
EOF

    # Create docker-compose files
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  gateway_ecu:
    build: ./gateway_ecu
    container_name: gateway_ecu
    networks:
      - can_network
      - external_network
    ports:
      - "8080:8080"
      - "8081:8081"
    environment:
      - CAN_INTERFACE=vcan0
    privileged: true
    
  infotainment_ecu:
    build: ./infotainment_ecu
    container_name: infotainment_ecu
    networks:
      - can_network
      - external_network
    ports:
      - "8888:8888"
      - "9999:9999"
    environment:
      - CAN_INTERFACE=vcan0
    privileged: true
    
  engine_ecu:
    build: ./engine_ecu
    container_name: engine_ecu
    networks:
      - can_network
    environment:
      - CAN_INTERFACE=vcan0
    privileged: true
    
  can_setup:
    image: alpine:latest
    container_name: can_setup
    command: |
      sh -c "
        apk add --no-cache iproute2 can-utils
        ip link add dev vcan0 type vcan
        ip link set up vcan0
        sleep infinity
      "
    networks:
      - can_network
    privileged: true
    
networks:
  can_network:
    driver: bridge
    internal: true
  external_network:
    driver: bridge
EOF

    # Create exploit files
    cat > exploits/client_example.py << 'EOF'
import websocket
import json
import hmac
import hashlib

class CANClient:
    def __init__(self, server_url):
        self.server_url = server_url
        self.ws = None
        self.session_id = None
        
    def connect(self):
        self.ws = websocket.WebSocket()
        self.ws.connect(self.server_url)
        welcome = json.loads(self.ws.recv())
        return welcome['challenge']
        
    def authenticate(self, challenge):
        secret_key = b"CTF_CAN_GATEWAY_SECRET_2024"
        response = hmac.new(secret_key, challenge.encode(), hashlib.sha256).hexdigest()
        auth_msg = {"type": "auth", "challenge": challenge, "response": response}
        self.ws.send(json.dumps(auth_msg))
        result = json.loads(self.ws.recv())
        return result['type'] == 'auth_success'
        
    def send_can_message(self, can_id, data):
        message = {"type": "can_send", "can_id": can_id, "data": data}
        self.ws.send(json.dumps(message))

if __name__ == "__main__":
    client = CANClient("ws://localhost:8080")
    challenge = client.connect()
    if client.authenticate(challenge):
        print("Authenticated!")
EOF

    # Create setup scripts
    cat > scripts/start_ctf.sh << 'EOF'
#!/bin/bash
docker-compose up -d
echo "CTF Started!"
echo "Gateway: ws://localhost:8080"
echo "Infotainment: http://localhost:8888"
EOF

    chmod +x scripts/start_ctf.sh

    # Create documentation
    cat > README.md << 'EOF'
# Automotive CTF

## Quick Start
1. Run `./master_setup.sh`
2. Run `./scripts/start_ctf.sh`
3. Access http://localhost:8888

## Goal
Find the flag in the infotainment ECU!

## Tools
- Gateway: ws://localhost:8080
- Infotainment: http://localhost:8888
EOF

    # Generate initial flags
    echo "FLAG{3ng1n3_s3cur3_$(openssl rand -hex 8)}" > engine_ecu/secret.txt
    
    print_success "All files created"
}

# Setup Python environment
setup_python_env() {
    print_info "Setting up Python environment..."
    
    python3 -m venv venv
    source venv/bin/activate
    
    pip install --upgrade pip
    pip install wheel setuptools
    
    # Install exploit tools
    pip install pwntools websocket-client requests python-can
    
    print_success "Python environment ready"
}

# Build Docker images
build_docker_images() {
    print_info "Building Docker images..."
    
    docker-compose build
    
    print_success "Docker images built"
}

# Verify installation
verify_installation() {
    print_info "Verifying installation..."
    
    # Check Docker
    docker --version || print_error "Docker not installed"
    docker-compose --version || print_error "Docker Compose not installed"
    
    # Check Python
    python3 --version || print_error "Python 3 not installed"
    
    # Check tools
    which nmap || print_warning "nmap not installed"
    which nc || print_warning "netcat not installed"
    
    print_success "Installation verified"
}

# Main setup function
main() {
    echo "======================================"
    echo "Automotive CTF Complete Setup"
    echo "======================================"
    
    check_root
    create_directory_structure
    create_all_files
    setup_python_env
    build_docker_images
    verify_installation
    
    echo ""
    echo "======================================"
    print_success "Setup Complete!"
    echo "======================================"
    echo ""
    echo "To start the CTF:"
    echo "  cd automotive_ctf"
    echo "  ./scripts/start_ctf.sh"
    echo ""
    echo "Access points:"
    echo "  Gateway: ws://localhost:8080"
    echo "  Infotainment: http://localhost:8888"
    echo ""
    echo "Happy Hacking!"
}

# Run main function
main