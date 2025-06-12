#!/bin/bash
set -e

# CAN 커널 모듈 로드 (컨테이너가 privileged 모드일 때만 작동)
modprobe can
modprobe can_raw
modprobe vcan

# vcan 인터페이스 생성 및 설정
ip link add dev vcan0 type vcan || true
ip link set up vcan0

# CAN 상태 확인
ip link show vcan0

# 메인 프로그램 실행
exec python engine_ecu.py
