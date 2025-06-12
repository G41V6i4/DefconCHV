FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    can-utils \
    iproute2 \
    gdb \
    net-tools \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY infotainment_simulator.c .
COPY Makefile .
COPY infotainment.conf .

RUN mkdir -p /app/media/songs /app/media/config
RUN echo "Admin password: Sup3rS3cr3t!" > /app/media/config/admin.txt

RUN make vulnerable

RUN echo "FLAG{1nf0t41nm3nt_pwn3d_$(openssl rand -hex 8)}" > /flag.txt
RUN chmod 644 /flag.txt

ENV CAN_INTERFACE=vcan0

EXPOSE 8888 9999

CMD ["./infotainment_simulator"]
