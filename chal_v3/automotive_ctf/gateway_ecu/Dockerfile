FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    net-tools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway_sim.py .
COPY auth_protocol.py .
COPY routing_rules.json .

RUN mkdir -p /var/log/gateway

ENV CAN_INTERFACE=vcan0
ENV PYTHONUNBUFFERED=1

EXPOSE 8080 8081

CMD ["python", "gateway_sim.py"]
