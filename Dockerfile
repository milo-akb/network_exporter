# Network Exporter Dockerfile
# Multi-protocol network monitoring exporter for Prometheus
# Supports ICMP, TCP, HTTP, HTTPS, DNS, UDP, and NTP protocols

# Use slim Python image
FROM python:3.11-slim

# Install ping, CA certificates, and build dependencies
RUN apt-get update && \
    apt-get install -y iputils-ping ca-certificates gcc libyaml-dev && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy dependency manifest first for better Docker cache reuse
COPY requirement.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirement.txt

# Copy project files
COPY network_exporter.py .

# Expose Prometheus metrics port
EXPOSE 8000

# Environment variables for customization
# PING_INTERVAL: seconds between probe cycles (default: 10)
# EXPORTER_PORT: HTTP port for metrics endpoint (default: 8000)
ENV PING_INTERVAL=10 \
    EXPORTER_PORT=8000

# Note: config.yaml must be volume-mounted at runtime:
# docker run -p 8000:8000 -v $(pwd)/config.yaml:/app/config.yaml network-exporter

# Run the exporter
CMD ["python", "network_exporter.py"]
