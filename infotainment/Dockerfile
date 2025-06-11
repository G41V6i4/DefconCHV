FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    kmod \
    gcc \
    libc6-dev \
    socat \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 소스 파일들 복사
COPY . .

# 실행 권한 부여
RUN chmod +x start_services.sh

# 미리 컴파일해서 문제 확인
RUN make clean && make

EXPOSE 1234

CMD ["./start_services.sh"]