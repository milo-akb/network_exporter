# Network Exporter

Multi-protocol network monitoring exporter for Prometheus. Monitors reachability and latency across ICMP, TCP, HTTP/HTTPS, DNS, UDP, and NTP protocols.

## Features

- **7 Protocols**: ICMP (ping), TCP, HTTP/HTTPS, DNS, UDP, NTP
- **Real-time Metrics**: Latency, packet loss, success rates, error counters
- **Hot-reload Config**: Changes to `config.yaml` apply automatically
- **Thread-safe**: Parallel probe execution with thread safety
- **Docker Ready**: Containerized deployment with health checks
- **Prometheus Compatible**: Metrics exposed in Prometheus format

## Quick Start

### Prerequisites
- Docker 20.10+
- Docker Compose (optional)

### Deploy

```bash
# Build image
docker build -t network-exporter:1.0 .

# Run container
docker run -d \
  --name network-exporter \
  --restart unless-stopped \
  -p 8000:8000 \
  -v $(pwd)/config.yaml:/app/config.yaml \
  network-exporter:1.0

# Verify
curl http://localhost:8000/metrics
```

## Configuration

Edit `config.yaml` with targets:

```yaml
targets:
  - address: 8.8.8.8
    protocol: icmp
    labels:
      name: "google_dns"
      location: "global"

  - address: example.com
    protocol: http
    port: 80
    labels:
      name: "example_web"
      location: "global"
```

## Metrics

Metrics are exposed at `http://localhost:8000/metrics` in Prometheus format.

For each target and protocol:
- `network_<protocol>_latency_avg_ms` - Average latency
- `network_<protocol>_success_rate` - Success rate (0-1)
- `network_<protocol>_error_timeout_count` - Timeout errors
- `network_<protocol>_uptime_seconds` - Total uptime
- `network_<protocol>_downtime_seconds` - Total downtime

## Supported Protocols

| Protocol | Probe Type | Latency Meaning |
|----------|-----------|-----------------|
| ICMP | System ping | Round-trip time |
| TCP | Socket connect | Connection time |
| HTTP | GET request | Request round-trip |
| HTTPS | GET request (TLS) | Request round-trip |
| DNS | A record lookup | Lookup duration |
| UDP | Send datagram | Send duration |
| NTP | NTP request | Server delay |

## Environment Variables

```bash
PING_INTERVAL=10        # Probe interval (seconds, default 10)
EXPORTER_PORT=8000      # Metrics port (default 8000)
```

## Commands

```bash
# View logs
docker logs -f network-exporter

# Stop
docker stop network-exporter

# Restart
docker restart network-exporter

# Remove
docker stop network-exporter && docker rm network-exporter
```

## Prometheus Integration

Add to `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'network-exporter'
    static_configs:
      - targets: ['localhost:8000']
```

## Docker Compose

```bash
docker-compose up -d
```

