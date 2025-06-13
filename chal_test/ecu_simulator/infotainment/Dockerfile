FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    kmod \
    net-tools \
    netcat \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Custom CAN tools 설치
COPY cansend /usr/local/bin/cansend
COPY candump /usr/local/bin/candump
RUN chmod +x /usr/local/bin/cansend /usr/local/bin/candump

# 취약한 펌웨어 및 디버그 인터페이스
COPY firmware/ /opt/firmware/
COPY debug_interface.py /opt/debug_interface.py

# SSH 서비스는 제거하고 간단한 TCP 서비스로 대체
COPY infotainment_service.py /opt/infotainment_service.py

WORKDIR /opt
EXPOSE 1234

CMD ["python3", "infotainment_service.py"]
