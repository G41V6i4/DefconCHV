#!/bin/bash

echo "Starting Infotainment ECU..."

# CAN 설정 (에러 무시)
modprobe can 2>/dev/null || true
modprobe can_raw 2>/dev/null || true  
modprobe vcan 2>/dev/null || true
ip link add dev vcan0 type vcan 2>/dev/null || true
ip link set up vcan0 2>/dev/null || true

cd /app

# 기존 프로세스 정리
pkill -f infotainment_service 2>/dev/null || true
pkill -f socat 2>/dev/null || true

# 컴파일
make clean && make

# 직접 실행 (socat 없이)
echo "Starting infotainment service on port 1234..."
./infotainment_service