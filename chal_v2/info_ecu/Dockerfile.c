FROM ubuntu:20.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    can-utils \
    iproute2 \
    gdb \
    socat \
    net-tools \
    mplayer \
    curl \
    python3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy source files
COPY infotainment_simulator.c .
COPY Makefile .
COPY infotainment.conf .

# Create media directory with some files
RUN mkdir -p /app/media/songs /app/media/config
RUN echo "Sensitive config data" > /app/media/config/secret.conf
RUN echo "Admin password: Sup3rS3cr3t!" > /app/media/config/admin.txt

# Build the vulnerable binary
RUN make vulnerable

# Disable ASLR for consistent exploitation
RUN echo 0 > /proc/sys/kernel/randomize_va_space

# Create a flag file in the root directory
RUN echo "FLAG{1nf0t41nm3nt_pwn3d!}" > /flag.txt
RUN chmod 644 /flag.txt

# Set environment
ENV CAN_INTERFACE=vcan0

# Expose web server port
EXPOSE 8888 9999

# Run the vulnerable infotainment system
CMD ["./infotainment_simulator"]