#!/bin/bash

# CAN 모듈 로드
modprobe can
modprobe can_raw
modprobe vcan

# vcan 인터페이스 설정
ip link add dev vcan0 type vcan
ip link set up vcan0

# 서비스 컴파일
cd /app
make clean
make

# 서비스 시작 (socat으로 포트 1234에 바인딩)
socat TCP-LISTEN:1234,reuseaddr,fork EXEC:./infotainment_service
