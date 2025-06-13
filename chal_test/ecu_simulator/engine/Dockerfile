FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    iproute2 \
    kmod \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Custom CAN tools
COPY cansend /usr/local/bin/cansend  
COPY candump /usr/local/bin/candump
RUN chmod +x /usr/local/bin/cansend /usr/local/bin/candump

COPY engine_ecu.py /opt/engine_ecu.py

WORKDIR /opt
CMD ["python3", "engine_ecu.py"]
