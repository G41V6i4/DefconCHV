# ./can_monitor/Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY . /app/

RUN chmod +x /app/can_monitor.py
RUN pip install argparse

# 실행 스크립트 생성
RUN echo '#!/bin/bash\n\
if [ "$1" = "vcan0" ] || [ "$1" = "vcan1" ] || [ "$1" = "" ]; then\n\
  python3 /app/can_monitor.py\n\
else\n\
  echo "Usage: candump [interface]"\n\
  echo "Interface is optional. When provided, it is ignored as this is a TCP-based monitor."\n\
fi\n\
' > /app/candump && chmod +x /app/candump

# PATH에 추가
ENV PATH="/app:${PATH}"

CMD ["bash"]
