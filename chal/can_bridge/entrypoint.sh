#!/bin/bash
set -e

# vcan 인터페이스 설정
modprobe can
modprobe can_raw
modprobe vcan

# 두 개의 vcan 인터페이스 생성
ip link add dev vcan0 type vcan || true
ip link add dev vcan1 type vcan || true
ip link set up vcan0
ip link set up vcan1

# vcan 인터페이스 상태 확인
ip link show vcan0
ip link show vcan1

# CAN 메시지 브릿지 실행
exec python can_bridge.py
