FROM python:3.9-slim

WORKDIR /app

# CAN 도구 설치
RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    kmod \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 9999

CMD ["python", "gateway.py"]
