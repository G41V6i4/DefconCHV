echo "Building ECU CTF Infrastructure..."

# 펌웨어 빌드
echo "1. Building firmware..."
cd firmware
python3 build_firmware.py
cd ..

# Docker 이미지 빌드
echo "2. Building Docker images..."
docker compose build

echo "3. Setting up shared infrastructure..."
docker compose up -d 

echo "Build complete!"
echo "Start the CTF manager with: docker-compose up ctf-manager"
