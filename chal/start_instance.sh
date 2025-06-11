#!/bin/bash

# 사용자 ID 생성 (랜덤 문자열)
USER_ID=$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 8 | head -n 1)

# 사용 가능한 포트 찾기
PORT=$(comm -23 <(seq 10000 11000 | sort) <(ss -tan | awk '{print $4}' | cut -d':' -f2 | sort -u) | head -n 1)

echo "Starting CTF instance for user $USER_ID on port $PORT"

# 환경 변수 설정 및 컨테이너 시작
USER_ID=$USER_ID PORT=$PORT docker-compose up -d

echo "Instance ready! Connect to Infotainment ECU: nc localhost $PORT"
echo "Your unique instance ID: $USER_ID"
