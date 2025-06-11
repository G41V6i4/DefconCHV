FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    can-utils \
    iproute2 \
    net-tools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY gateway_sim.py .
COPY auth_protocol.py .
COPY routing_rules.json .

# Create necessary directories
RUN mkdir -p /var/log/gateway /var/run

# Set environment variables
ENV CAN_INTERFACE=vcan0
ENV PYTHONUNBUFFERED=1

# Expose ports
EXPOSE 8080 8081

# Run the gateway
CMD ["python", "gateway_sim.py"]