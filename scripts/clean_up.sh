#!/bin/bash

echo "Cleaning up ECU CTF environment..."

# 모든 사용자 컨테이너 정리
echo "Stopping user containers..."
docker ps -a --filter "name=infotainment_session_*" --format "{{.Names}}" | xargs -r docker rm -f

# 사용되지 않는 네트워크 정리
echo "Cleaning up networks..."
docker network prune -f

# 사용되지 않는 이미지 정리 (선택사항)
read -p "Remove unused images? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    docker image prune -f
fi

echo "Cleanup complete!"
