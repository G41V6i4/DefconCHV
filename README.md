# ECU CTF Challenge 🚗💻

Multi-stage automotive ECU penetration testing challenge for cybersecurity competitions.

## Overview

This challenge simulates a realistic automotive ECU network where participants must:
1. **Firmware Analysis** - Reverse engineer infotainment firmware
2. **Binary Exploitation** - Exploit vulnerabilities to gain shell access  
3. **CAN Bus Analysis** - Analyze and manipulate CAN network traffic
4. **Protocol Security** - Bypass gateway authentication mechanisms
5. **System Compromise** - Access critical engine control systems

## Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Infotainment   │    │    Gateway      │    │     Engine      │
│      ECU        │◄──►│      ECU        │◄──►│      ECU        │
│   (Per User)    │    │   (Shared)      │    │   (Shared)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
│                        │                        │
└────────────────────────┼────────────────────────┘
                         │
                  CAN Bus Network
```
## Quick Start

### Prerequisites
- Docker & Docker Compose
- Linux environment (WSL2 supported)
- 4GB+ RAM for multiple concurrent users

### Deployment

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/ecu-ctf-challenge.git
cd ecu-ctf-challenge

# Build and start infrastructure
chmod +x scripts/*.sh
./scripts/build_all.sh

# Start CTF platform
docker-compose up -d

# Verify deployment
curl http://localhost:8080/admin/status
For Participants
bash# 1. Create challenge instance
curl -X POST http://localhost:8080/start
# Response: {"session_id": "...", "port": 12345, "firmware_download": "..."}

# 2. Download firmware for analysis
wget http://localhost:8080/firmware/SESSION_ID

# 3. Connect to infotainment ECU
nc localhost PORT
Challenge Stages
Stage 1: Firmware Analysis

Goal: Find hidden debug functionality in firmware binary
Skills: Binary analysis, string extraction, reverse engineering
Tools: strings, objdump, Ghidra, radare2

Stage 2: Binary Exploitation

Goal: Exploit infotainment service to gain shell access
Skills: Buffer overflow, command injection, exploitation
Vulnerability: Debug mode + command injection

Stage 3: CAN Network Discovery

Goal: Analyze CAN bus communication protocols
Skills: Network analysis, protocol understanding
Tools: candump, cansend, custom CAN tools

Stage 4: Gateway Authentication Bypass

Goal: Bypass security access mechanism
Skills: Cryptographic analysis, timing attacks
Vulnerability: Weak seed-key algorithm (XOR-based)

Stage 5: Engine ECU Compromise

Goal: Access engine control system and retrieve flag
Skills: UDS protocol, diagnostic services
Final: Extract flag from engine ECU memory

Infrastructure Management
Monitoring
bash# Check system status
curl http://localhost:8080/admin/status

# View active sessions
docker ps --filter "name=infotainment_session_*"

# Check resource usage
docker stats
Cleanup
bash# Clean user sessions
./scripts/cleanup.sh

# Full reset
docker-compose down
docker system prune -f
Security Considerations

Isolation: Each user gets isolated infotainment container
Resource Limits: Automatic session timeout (1 hour)
Network Security: Containers run with minimal privileges
Monitoring: All activities logged for forensics

File Structure
ecu-ctf-challenge/
├── manager/           # CTF orchestration server
├── infotainment/      # User-specific ECU containers  
├── gateway/           # Shared gateway ECU
├── engine/            # Shared engine ECU
├── firmware/          # Binary firmware files
├── scripts/           # Deployment automation
├── tools/             # Analysis utilities
├── docs/              # Challenge documentation
└── tests/             # Integration tests
Contributing

Fork the repository
Create feature branch (git checkout -b feature/amazing-feature)
Commit changes (git commit -m 'Add amazing feature')
Push to branch (git push origin feature/amazing-feature)
Open Pull Request

License
This project is licensed under the MIT License - see LICENSE file.
Authors

Your Name - Initial work - YourGitHub

Acknowledgments

Automotive security research community
CTF challenge design best practices
Docker containerization patterns


🏁 Ready to hack some cars? Start your engines! 🏎️
