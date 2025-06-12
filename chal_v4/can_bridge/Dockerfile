FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY can_bridge.py .

EXPOSE 12345

CMD ["python3", "-u", "can_bridge.py"]