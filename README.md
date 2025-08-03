# ECU CTF Challenge 🚗💻

Multi-stage automotive ECU penetration testing challenge for cybersecurity competitions.

## 📋 프로젝트 종합 분석

### 🎯 **프로젝트 개요**
자동차 ECU(Electronic Control Unit) 네트워크를 시뮬레이션한 **CTF(Capture The Flag) 보안 챌린지** 환경입니다. 참가자들이 5단계의 해킹 과정을 통해 자동차 시스템을 침투하는 문제입니다.

### 🏗️ **아키텍처**
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Infotainment   │◄──►│    Gateway      │◄──►│     Engine      │
│      ECU        │    │      ECU        │    │      ECU        │
│   (Per User)    │    │   (Shared)      │    │   (Shared)      │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 📁 **주요 구성요소**

#### **1. Manager (Flask 서버) - `/manager/`**
- **역할**: CTF 세션 관리 및 오케스트레이션
- **핵심 기능**:
  - 사용자별 Infotainment 컨테이너 생성/관리
  - 펌웨어 다운로드 제공
  - 공유 인프라(Gateway/Engine) 관리
  - 실시간 모니터링 대시보드
- **의존성**: Flask 2.3.2, Docker 6.1.3

#### **2. Infotainment ECU - `/infotainment/`**
- **역할**: 초기 진입점 (사용자별 개별 환경)
- **핵심 파일**:
  - `info.c`: 취약한 인포테인먼트 바이너리 (버퍼 오버플로우, 권한 상승)
  - `can_daemon.py`, `candump.py`, `cansend.py`: CAN 통신 도구
- **취약점**: 디버그 모드 활성화, 메모리 오버플로우

#### **3. Gateway ECU - `/gateway/`**
- **역할**: CAN 네트워크 게이트웨이 (공유 환경)
- **핵심 기능**:
  - UDS(Unified Diagnostic Services) 보안 인증
  - CAN 메시지 라우팅 및 브로커
  - 세션별 보안 레벨 관리
  - 타이밍 어택에 취약한 암호화 알고리즘
- **의존성**: python-can 4.2.2

#### **4. Engine ECU - `/engine/`**
- **역할**: 최종 목표 시스템 (공유 환경)
- **핵심 기능**:
  - UDS 진단 서비스 처리
  - 보안 접근 제어 (시드-키 알고리즘)
  - 최종 플래그 보관: `CTF{engine_ecu_compromised_final_flag}`

### 🔧 **기술 스택**

#### **백엔드**
- **Python 3.x**: 주요 서비스 로직
- **Flask 2.3.2**: 웹 서버
- **Docker & Docker Compose**: 컨테이너화
- **C**: 취약한 바이너리 (info.c)

#### **프로토콜 & 통신**
- **CAN Bus**: 자동차 네트워크 시뮬레이션
- **UDS (Unified Diagnostic Services)**: 진단 프로토콜
- **ISO-TP**: 전송 프로토콜
- **JSON**: 메시지 포맷

#### **보안 요소**
- **XOR 암호화**: 간단한 문자열 암호화
- **시드-키 인증**: 게이트웨이 보안 우회
- **PRNG**: 세션별 난수 생성

### 🎮 **챌린지 단계**

1. **펌웨어 분석**: 바이너리에서 숨겨진 디버그 기능 발견
2. **바이너리 익스플로잇**: 버퍼 오버플로우로 쉘 획득
3. **CAN 네트워크 분석**: 차량 내부 통신 분석
4. **게이트웨이 우회**: UDS 보안 인증 우회
5. **엔진 ECU 접근**: 최종 플래그 획득

### 🛡️ **보안 고려사항**

#### **취약점 (의도된)**
- 버퍼 오버플로우 (system_diagnostics():355)
- 함수 포인터 오버라이트 (device_manager)
- 약한 암호화 (XOR 0x37)
- 타이밍 어택 (gateway.py:91-112)
- 고정 시드 (engine.py:160)

#### **보안 기능**
- 컨테이너 격리
- 세션별 타임아웃 (1시간)
- 최소 권한 실행
- 로깅 및 모니터링

### 🚀 **배포 환경**
- **OS**: Linux (Ubuntu 22.04 기반)
- **포트**: 8080 (관리), 9999 (CAN 브로커), 20000-30000 (동적 할당)
- **네트워크**: 브리지 네트워크 (ecu_shared_network)
- **리소스**: 4GB+ RAM 권장

이 프로젝트는 **교육용 보안 실습**을 위한 잘 설계된 CTF 환경으로, 실제 자동차 보안 연구의 기본 개념들을 안전하게 학습할 수 있도록 구성되어 있습니다.

---

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
