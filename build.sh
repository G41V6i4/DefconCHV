docker build -t ecu_manager:latest ./manager/
docker build -t ecu_gateway:latest ./gateway/
docker build -t ecu_engine:latest ./engine/
docker build -t ecu_infotainment:latest ./infotainment/

# 빌드된 이미지 확인
docker images | grep ecu
