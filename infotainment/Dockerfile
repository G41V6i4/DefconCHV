FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive \
    LC_CTYPE=C.UTF-8

# 포트 설정
EXPOSE 1234

# 레포지토리 변경 (빠른 설치)
RUN sed -i "s/archive.ubuntu/mirror.kakao/g" /etc/apt/sources.list

# 업데이트 및 필수 패키지 설치
RUN apt update && apt upgrade -y
RUN apt install -y xinetd gcc make python3
RUN apt install -y --no-install-recommends tzdata

# 타임존 설정
RUN echo "Asia/Seoul" > /etc/timezone
RUN rm -f /etc/localtime
RUN dpkg-reconfigure --frontend noninteractive tzdata

# xinetd 서비스 설정
RUN touch /var/log/ecu.log
RUN touch /etc/xinetd.d/ecu
RUN echo "service ecu                         " >> /etc/xinetd.d/ecu
RUN echo "{                                  " >> /etc/xinetd.d/ecu
RUN echo "    flags = REUSE                  " >> /etc/xinetd.d/ecu
RUN echo "    disable = no                   " >> /etc/xinetd.d/ecu
RUN echo "    socket_type = stream           " >> /etc/xinetd.d/ecu
RUN echo "    wait = no                      " >> /etc/xinetd.d/ecu
RUN echo "    user = ecu                     " >> /etc/xinetd.d/ecu
RUN echo "    server = /home/ecu/infotainment_service" >> /etc/xinetd.d/ecu
RUN echo "    port = 1234                    " >> /etc/xinetd.d/ecu
RUN echo "    protocol = tcp                 " >> /etc/xinetd.d/ecu
RUN echo "    log_type = FILE /var/log/ecu.log" >> /etc/xinetd.d/ecu
RUN echo "    log_on_success = HOST DURATION EXIT" >> /etc/xinetd.d/ecu
RUN echo "}                                  " >> /etc/xinetd.d/ecu
RUN echo "ecu 1234/tcp" >> /etc/services

# 사용자 계정 설정
RUN useradd ecu -m -s /bin/bash
RUN echo "ecu:ecu123!" | chpasswd
RUN echo "root:root123!" | chpasswd

# ASLR 설정 (보안 강화)
RUN touch /etc/sysctl.d/01-disable-aslr.conf
RUN echo "kernel.randomize_va_space = 2" >> /etc/sysctl.d/01-disable-aslr.conf

# 보안 권한 설정


RUN chmod 600 /etc/passwd
RUN chmod 600 /etc/passwd-
RUN chmod 600 /etc/group
RUN chmod 600 /etc/group-
RUN chmod 600 /etc/shadow
RUN chmod 600 /etc/shadow-

# 소스 파일 복사 및 컴파일
COPY info.c /tmp/info.c
COPY Makefile /tmp/Makefile
COPY candump.py /tmp/candump.py
COPY cansend.py /tmp/cansend.py
RUN cd /tmp && make clean && make
RUN mv /tmp/infotainment_service /home/ecu/infotainment_service

# 플래그 생성
RUN echo "CTF{infotainment_ecu_compromised_stage1}" > /home/ecu/flag.txt

# 홈 디렉토리 정리
RUN rm -rf /home/ecu/.bash_history
RUN rm -rf /home/ecu/.bash_logout
RUN rm -rf /home/ecu/.bashrc
RUN rm -rf /home/ecu/.profile
RUN rm -rf /home/ecu/.cache
RUN ln -s /dev/null /home/ecu/.bash_history
RUN ln -s /dev/null /home/ecu/.bash_logout
RUN ln -s /dev/null /home/ecu/.bashrc
RUN ln -s /dev/null /home/ecu/.profile
RUN ln -s /dev/null /home/ecu/.cache

# 권한 설정
RUN chown ecu:ecu /home/ecu
RUN chown ecu:ecu /home/ecu/infotainment_service
RUN chown ecu:ecu /home/ecu/flag.txt
RUN chown ecu:ecu /tmp/cansend.py
RUN chown ecu:ecu /tmp/candump.py
RUN chmod 555 /tmp/cansend.py
RUN chmod 555 /tmp/candump.py
RUN chmod 500 /home/ecu
RUN chmod 555 /home/ecu/infotainment_service
RUN chmod 400 /home/ecu/flag.txt

RUN ln -sf "/tmp/cansend.py" /usr/local/bin/cansend
RUN ln -sf "/tmp/candump.py" /usr/local/bin/candump
# RUN modprobe can 2>/dev/null || true
# RUN modprobe can_raw 2>/dev/null || true  
# RUN modprobe vcan 2>/dev/null || true
# RUN ip link add dev vcan0 type vcan 2>/dev/null || true
# RUN ip link set up vcan0 2>/dev/null || true
# 임시 파일 정리
#RUN rm -rf /tmp/*

CMD ["/usr/sbin/xinetd", "-dontfork"]