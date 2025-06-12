FROM ubuntu:20.04

RUN apt-get update && apt-get install -y \
    gcc \
    xinetd \
    make \
    net-tools 
    #&& rm -rf /var/lib/apt/lists/*

# 사용자 생성
RUN useradd -m ctf

# 취약한 바이너리 컴파일 (보호 기법 비활성화)
COPY infotainment_ecu.c /tmp/
RUN gcc -o /home/ctf/infotainment_ecu /tmp/infotainment_ecu.c \
    -fno-stack-protector \
    -z execstack \
    -no-pie \
    -Wl,-z,norelro \
    && rm /tmp/infotainment_ecu.c

# 플래그 파일
COPY flag1.txt /home/ctf/flag1.txt
RUN chmod 444 /home/ctf/flag1.txt

# xinetd 설정
COPY xinetd_config /etc/xinetd.d/infotainment
RUN chmod 644 /etc/xinetd.d/infotainment

# 권한 설정
RUN chown -R ctf:ctf /home/ctf
RUN chmod 755 /home/ctf
RUN chmod 555 /home/ctf/infotainment_ecu

EXPOSE 1337

CMD ["/usr/sbin/xinetd", "-dontfork"]