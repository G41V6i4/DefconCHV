FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ecm.py .
COPY flag3.txt /tmp/flag3.txt

RUN chmod 444 /tmp/flag3.txt

CMD ["python3", "-u", "ecm.py"]