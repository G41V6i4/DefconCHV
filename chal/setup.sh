#!/bin/bash

# 색상 설정
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[*] ECU 시뮬레이터 해킹 환경 설정 스크립트${NC}"

# 필수 패키지 설치 확인
echo -e "${YELLOW}[*] 필수 패키지 설치 확인 중...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[!] Docker가 설치되지 않았습니다. 설치를 진행합니다...${NC}"
    sudo apt-get update
    sudo apt-get install -y docker.io docker-compose
else
    echo -e "${GREEN}[+] Docker 설치 확인 완료${NC}"
fi

if ! command -v candump &> /dev/null; then
    echo -e "${RED}[!] CAN 유틸리티가 설치되지 않았습니다. 설치를 진행합니다...${NC}"
    sudo apt-get update
    sudo apt-get install -y can-utils
else
    echo -e "${GREEN}[+] can-utils 설치 확인 완료${NC}"
fi

# 커널 모듈 로드 (호스트에서)
echo -e "${YELLOW}[*] 가상 CAN 커널 모듈 로드 중...${NC}"
if ! lsmod | grep -q "^vcan"; then
    sudo modprobe can
    sudo modprobe can_raw
    sudo modprobe vcan
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] vcan 모듈 로드 실패${NC}"
        exit 1
    fi
fi
echo -e "${GREEN}[+] vcan 모듈 로드 완료${NC}"

# 가상 CAN 인터페이스 설정 (호스트에서)
echo -e "${YELLOW}[*] 가상 CAN 인터페이스 설정 중...${NC}"
if ! ip link show vcan0 &> /dev/null; then
    sudo ip link add dev vcan0 type vcan
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] vcan0 인터페이스 생성 실패${NC}"
        exit 1
    fi
    sudo ip link set up vcan0
    echo -e "${GREEN}[+] vcan0 인터페이스 생성 및 활성화 완료${NC}"
else
    echo -e "${GREEN}[+] vcan0 인터페이스가 이미 존재합니다${NC}"
    sudo ip link set up vcan0
fi
if ! ip link show vcan1 &> /dev/null; then
    sudo ip link add dev vcan1 type vcan
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] vcan1 인터페이스 생성 실패${NC}"
        exit 1
    fi
    sudo ip link set up vcan1
    echo -e "${GREEN}[+] vcan1 인터페이스 생성 및 활성화 완료${NC}"
else
    echo -e "${GREEN}[+] vcan1 인터페이스가 이미 존재합니다${NC}"
    sudo ip link set up vcan1
fi
# 펌웨어 파일 생성
echo -e "${YELLOW}[*] 테스트 펌웨어 파일 생성 중...${NC}"
cd infotainment
python3 create_firmware.py
cd ..

# Docker 컨테이너 빌드 및 실행
echo -e "${YELLOW}[*] Docker 컨테이너 빌드 및 실행 중...${NC}"
sudo docker compose down
sudo docker compose build
sudo docker compose up -d --build

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] Docker 컨테이너 실행 실패${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Docker 컨테이너 실행 완료${NC}"

# 접속 정보 표시
echo -e "\n${BLUE}=== ECU 시뮬레이터 해킹 환경 구성 완료 ===${NC}"
echo -e "${GREEN}인포테인먼트 ECU 연결 방법: nc localhost 1337${NC}"
echo -e "${GREEN}CAN 트래픽 모니터링: candump vcan0${NC}"
echo -e "${YELLOW}첫 번째 단계: firmware.bin 파일을 분석하여 디버그 명령어를 찾으세요.${NC}"
echo -e "${YELLOW}문제 해결 목표: 엔진 ECU에 접근하여 플래그를 획득하세요.${NC}"