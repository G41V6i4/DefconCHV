FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    kmod \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# CAN Broker 설치
COPY can_broker.py /opt/can_broker.py
COPY gateway_ecu.py /opt/gateway_ecu.py

# Custom CAN tools
COPY cansend /usr/local/bin/cansend
COPY candump /usr/local/bin/candump
RUN chmod +x /usr/local/bin/cansend /usr/local/bin/candump

WORKDIR /opt

# CAN Broker와 Gateway ECU를 병렬로 실행
CMD python3 can_broker.py & python3 gateway_ecu.py && wait
