FROM ubuntu:22.04

WORKDIR /app

# 필요한 패키지 설치
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    can-utils \
    iproute2 \
    netcat \
    procps \
    build-essential \
    libsocketcan-dev \
    && rm -rf /var/lib/apt/lists/*

# Python 패키지 설치 (필요한 경우)
RUN pip3 install python-can

# 포트 노출 (TCP 통신용)
EXPOSE 1337

# 컨테이너 시작 시 실행할 명령어
CMD ["/app/info"]