FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway_ecu.py .
COPY flag2.txt /tmp/flag2.txt

RUN chmod 444 /tmp/flag2.txt

CMD ["python3", "-u", "gateway_ecu.py"]