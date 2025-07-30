FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive \
    LC_CTYPE=C.UTF-8

# 포트 설정
EXPOSE 1234

# 업데이트 및 필수 패키지 설치
RUN apt update && apt upgrade -y
RUN apt install -y xinetd gcc make python3 qemu-user-static
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
RUN echo "    server = /home/ecu/run.sh" >> /etc/xinetd.d/ecu
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
COPY can_daemon.py /tmp/can_daemon.py
COPY candump.py /tmp/candump.py
COPY cansend.py /tmp/cansend.py
COPY infotainment_service /home/ecu/infotainment_service
COPY run.sh /home/ecu/run.sh

# CAN 도구 설치
RUN cp /tmp/can_daemon.py /opt/can_daemon.py
RUN cp /tmp/cansend.py /opt/cansend.py  
RUN cp /tmp/candump.py /opt/candump.py
RUN chmod +x /opt/can_daemon.py /opt/cansend.py /opt/candump.py

# CAN 도구 심볼릭 링크
RUN ln -sf /opt/cansend.py /usr/local/bin/cansend
RUN ln -sf /opt/candump.py /usr/local/bin/candump

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
RUN chown ecu:ecu /home/ecu/run.sh
RUN chmod 500 /home/ecu
RUN chmod 555 /home/ecu/infotainment_service
RUN chmod 555 /home/ecu/run.sh

# CAN 데몬을 위한 디렉토리 생성 및 권한 설정
RUN mkdir -p /tmp/can_daemon
RUN chmod 777 /tmp/can_daemon
RUN chown nobody:nogroup /tmp/can_daemon

# 시작 스크립트 생성
RUN echo '#!/bin/bash' > /opt/start.sh
RUN echo '# CAN 데몬을 백그라운드로 시작' >> /opt/start.sh
RUN echo 'python3 /opt/can_daemon.py &' >> /opt/start.sh
RUN echo '# 파이프 생성 대기' >> /opt/start.sh
RUN echo 'sleep 2' >> /opt/start.sh
RUN echo '# 파이프 권한 설정' >> /opt/start.sh
RUN echo 'chmod 666 /tmp/can_daemon/send 2>/dev/null || true' >> /opt/start.sh
RUN echo 'chmod 666 /tmp/can_daemon/recv 2>/dev/null || true' >> /opt/start.sh
RUN echo '# xinetd 시작' >> /opt/start.sh
RUN echo 'exec /usr/sbin/xinetd -dontfork' >> /opt/start.sh
RUN chmod +x /opt/start.sh

# 임시 파일 정리
RUN rm -rf /tmp/info.c /tmp/Makefile /tmp/*.py

CMD ["/opt/start.sh"]