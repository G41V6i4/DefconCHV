#!/bin/bash

echo "Building ECU simulator images..."

# Custom CAN tools를 각 디렉토리에 복사
cp ../can_broker.py gateway/
cp ../cansend.py infotainment/cansend
cp ../candump.py infotainment/candump
cp ../cansend.py gateway/cansend  
cp ../candump.py gateway/candump
cp ../cansend.py engine/cansend
cp ../candump.py engine/candump

# 펌웨어 디렉토리 생성 (1단계용)
mkdir -p infotainment/firmware
echo "FIRMWARE_BINARY_DATA_WITH_HIDDEN_DEBUG_STRINGS" > infotainment/firmware/infotainment.bin

# Docker 이미지 빌드
docker build -t ecu_infotainment:latest infotainment/
docker build -t ecu_gateway:latest gateway/
docker build -t ecu_engine:latest engine/

echo "ECU simulator images built successfully!"
echo "Use the main Flask application to start individual sessions."
