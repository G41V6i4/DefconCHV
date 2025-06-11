FROM python:3.9-slim

RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine_simulator_secure.py .
COPY uds_service.py .
COPY secret.txt .

ENV CAN_INTERFACE=vcan0

CMD ["python", "engine_simulator_secure.py"]
