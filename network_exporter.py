import os
import time
import threading
import statistics
import subprocess
import re
import yaml
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from prometheus_client import start_http_server, Gauge, Histogram, Counter
from pydantic import BaseModel
import socket
import requests
import ntplib
import dns.resolver
import dns.exception

#-----------------------------------------------Targets-------------------------------------------------------#
class Target(BaseModel):
    address: str
    ping_count: int = 5
    timeout: float = 1.0
    packet_size: int = 64
    protocol: str = 'icmp'  # Options: icmp, tcp, http, https, dns, udp, ntp
    port: int = 80  # for tcp/http/udp
    dns_server: str | None = None  # for dns; if unset, uses system resolver
    dns_port: int = 53  # for dns when dns_server is set
    ntp_version: int = 3  # for ntp
    labels: dict = {}

CONFIG_PATH = 'config.yaml'
PING_INTERVAL = int(os.getenv("PING_INTERVAL", 10))
EXPORTER_PORT = int(os.getenv("EXPORTER_PORT", 8000))

#-----------------------------------------------Logging-------------------------------------------------------#
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

#-----------------------------------------------Metrics-------------------------------------------------------#
# Define separate metrics for each protocol
metrics = {
    'icmp': {
        'lat_avg': Gauge('network_icmp_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'lat_min': Gauge('network_icmp_latency_min_ms', 'Min latency', ['address', 'name', 'location']),
        'lat_max': Gauge('network_icmp_latency_max_ms', 'Max latency', ['address', 'name', 'location']),
        'lat_jitter': Gauge('network_icmp_latency_jitter_ms', 'Jitter', ['address', 'name', 'location']),
        'pkt_loss': Gauge('network_icmp_packet_loss_percent', 'Packet loss %', ['address', 'name', 'location']),
        'success': Gauge('network_icmp_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_icmp_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'error_timeout_count': Counter('network_icmp_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_icmp_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_icmp_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_icmp_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    },
    'tcp': {
        'lat_avg': Gauge('network_tcp_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'success': Gauge('network_tcp_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_tcp_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'error_timeout_count': Counter('network_tcp_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_tcp_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_tcp_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_tcp_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    },
    'http': {
        'lat_avg': Gauge('network_http_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'success': Gauge('network_http_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_http_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'response_code': Gauge('network_http_response_code', 'HTTP response code', ['address', 'name', 'location']),
        'error_timeout_count': Counter('network_http_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_http_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_http_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_http_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    },
    'https': {
        'lat_avg': Gauge('network_https_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'success': Gauge('network_https_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_https_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'response_code': Gauge('network_https_response_code', 'HTTPS response code', ['address', 'name', 'location']),
        'error_timeout_count': Counter('network_https_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_https_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_https_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_https_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    },
    'dns': {
        'lat_avg': Gauge('network_dns_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'success': Gauge('network_dns_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_dns_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'error_timeout_count': Counter('network_dns_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_dns_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_dns_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_dns_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    },
    'udp': {
        'lat_avg': Gauge('network_udp_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'success': Gauge('network_udp_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_udp_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'error_timeout_count': Counter('network_udp_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_udp_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_udp_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_udp_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    },
    'ntp': {
        'lat_avg': Gauge('network_ntp_latency_avg_ms', 'Average latency', ['address', 'name', 'location']),
        'success': Gauge('network_ntp_success_rate', 'Success rate (0-1)', ['address', 'name', 'location']),
        'lat_histogram': Histogram('network_ntp_latency_histogram_ms', 'Latency histogram', ['address', 'name', 'location'], buckets=[10, 50, 100, 200, 500, 1000]),
        'error_timeout_count': Counter('network_ntp_error_timeout_count', 'Timeout error count', ['address', 'name', 'location']),
        'error_connection_refused_count': Counter('network_ntp_error_connection_refused_count', 'Connection refused error count', ['address', 'name', 'location']),
        'uptime_seconds': Counter('network_ntp_uptime_seconds', 'Total uptime seconds', ['address', 'name', 'location']),
        'downtime_seconds': Counter('network_ntp_downtime_seconds', 'Total downtime seconds', ['address', 'name', 'location'])
    }
}


active_threads = {}
thread_stoppers = {}
active_targets = {}  # Store Target objects for metric cleanup
targets_lock = threading.Lock()
update_lock = threading.Lock()
last_config_reload_time = 0
MIN_RELOAD_INTERVAL = 2.0  # Debounce config reloads within 2 seconds
PING_LATENCY_PATTERN = re.compile(r"time[=<]\s*([0-9]+(?:\.[0-9]+)?)\s*ms", re.IGNORECASE)


def target_identity(target: Target):
    labels_tuple = tuple(sorted((target.labels or {}).items()))
    return (
        target.protocol,
        target.address,
        target.port,
        target.dns_server,
        target.dns_port,
        target.timeout,
        target.ping_count,
        target.packet_size,
        target.ntp_version,
        labels_tuple,
    )

def load_config():
    with open(CONFIG_PATH) as f:
        data = yaml.safe_load(f)
        targets = [Target(**t) for t in data.get('targets', [])]
        return targets


def format_probe_details(target: Target):
    if target.protocol == 'icmp':
        return f"ping_count={target.ping_count} timeout={target.timeout} packet_size={target.packet_size}"
    if target.protocol in ('tcp', 'http', 'https', 'udp'):
        return f"port={target.port} timeout={target.timeout}"
    if target.protocol == 'dns':
        resolver_target = target.dns_server if target.dns_server else 'system'
        return f"dns_server={resolver_target} dns_port={target.dns_port} timeout={target.timeout}"
    if target.protocol == 'ntp':
        return f"ntp_version={target.ntp_version} timeout={target.timeout}"
    return f"port={target.port} timeout={target.timeout}"

def update_targets():
    new_targets = load_config()
    new_target_dict = {}
    for t in new_targets:
        key = target_identity(t)
        if key in new_target_dict:
            logging.warning(f"Duplicate target definition detected and ignored: {t}")
            continue
        new_target_dict[key] = t

    threads_to_start = []
    removed_entries = []
    with update_lock:
        with targets_lock:
            # Queue new threads first, then start them outside the lock.
            for key, t in new_target_dict.items():
                if key not in active_threads:
                    logging.info(f"Starting probe: protocol={t.protocol} address={t.address} {format_probe_details(t)}")
                    stop_event = threading.Event()
                    thread = threading.Thread(target=ping_loop, args=(t, stop_event), daemon=True)
                    active_threads[key] = thread
                    thread_stoppers[key] = stop_event
                    active_targets[key] = t
                    threads_to_start.append(thread)

            # Detach removed targets from shared maps quickly, then stop/join outside lock.
            removed_keys = set(active_threads.keys()) - set(new_target_dict.keys())
            for key in removed_keys:
                t = active_targets[key]
                logging.info(f"Stopping probe: protocol={t.protocol} address={t.address} {format_probe_details(t)}")
                thread = active_threads.pop(key)
                stop_event = thread_stoppers.pop(key)
                active_targets.pop(key)
                removed_entries.append((thread, stop_event, t))

        for _, stop_event, _ in removed_entries:
            stop_event.set()

        for thread, _, _ in removed_entries:
            thread.join()

        for _, _, t in removed_entries:
            labels = t.labels
            for metric in metrics[t.protocol].values():
                metric.remove(t.address, labels.get('name', ''), labels.get('location', ''))

        for thread in threads_to_start:
            thread.start()
        logging.info(f"Config reload complete: {len(active_threads)} active probes")

class ConfigWatcher(FileSystemEventHandler):
    def on_modified(self, event):
        global last_config_reload_time
        if event.src_path.endswith(CONFIG_PATH):
            now = time.time()
            if now - last_config_reload_time >= MIN_RELOAD_INTERVAL:
                logging.info(f"Config modification detected, reloading targets")
                update_targets()
                last_config_reload_time = now
            else:
                logging.debug(f"Config modification ignored (debounced, {now - last_config_reload_time:.1f}s since last reload)")


def build_system_ping_command(address: str, timeout: float, packet_size: int):
    timeout_ms = max(1, int(timeout * 1000))
    if os.name == 'nt':
        # Windows ping timeout is in milliseconds.
        return ['ping', '-n', '1', '-w', str(timeout_ms), '-l', str(max(0, packet_size)), address]

    # Linux ping timeout is in seconds.
    timeout_sec = max(1, int(round(timeout)))
    return ['ping', '-c', '1', '-W', str(timeout_sec), '-s', str(max(0, packet_size)), address]


def parse_ping_latency_ms(output: str):
    match = PING_LATENCY_PATTERN.search(output or '')
    if not match:
        return None
    return float(match.group(1))


def classify_ping_failure(output: str):
    text = (output or '').lower()
    timeout_markers = [
        'timed out',
        '100% packet loss',
        '100.0% packet loss',
        'request timeout',
        'deadline exceeded',
    ]
    connection_markers = [
        'permission denied',
        'operation not permitted',
        'name or service not known',
        'unknown host',
        'temporary failure in name resolution',
        'destination host unreachable',
        'network is unreachable',
    ]

    if any(marker in text for marker in timeout_markers):
        return 'timeout'
    if any(marker in text for marker in connection_markers):
        return 'connection'
    return 'connection'


def probe_icmp_system_ping(address: str, timeout: float, packet_size: int):
    cmd = build_system_ping_command(address, timeout, packet_size)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(timeout + 1.0, 1.0),
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, 'timeout'
    except FileNotFoundError:
        logging.error('System ping command not found in PATH')
        return None, 'connection'

    output = f"{result.stdout}\n{result.stderr}".strip()
    latency_ms = parse_ping_latency_ms(output)

    if result.returncode == 0:
        if latency_ms is None:
            # Some ping variants may not expose RTT in a parseable format.
            latency_ms = timeout * 1000
        return latency_ms, 'success'

    return None, classify_ping_failure(output)


def probe_dns_lookup(address: str, timeout: float, dns_server: str | None = None, dns_port: int = 53):
    if dns_server:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [dns_server]
        resolver.port = dns_port
    else:
        resolver = dns.resolver.Resolver()

    resolver.timeout = timeout
    resolver.lifetime = timeout

    start = time.time()
    resolver.resolve(address, 'A')
    return (time.time() - start) * 1000

def ping_loop(target: Target, stop_event):
    address = target.address
    labels = target.labels
    label_values = {
        'address': address,
        'name': labels.get('name', ''),
        'location': labels.get('location', '')
    }

    while not stop_event.is_set():
        try:
            if target.protocol == 'icmp':
                latencies = []
                timeout_failures = 0
                connection_failures = 0
                for _ in range(target.ping_count):
                    latency_ms, status = probe_icmp_system_ping(address, target.timeout, target.packet_size)
                    if status == 'success' and latency_ms is not None:
                        latencies.append(latency_ms)
                    elif status == 'timeout':
                        timeout_failures += 1
                    else:
                        connection_failures += 1
                success_count = len(latencies)
                loss = (target.ping_count - success_count) / target.ping_count * 100
                success_rate = success_count / target.ping_count

                if timeout_failures:
                    metrics['icmp']['error_timeout_count'].labels(**label_values).inc(timeout_failures)
                if connection_failures:
                    metrics['icmp']['error_connection_refused_count'].labels(**label_values).inc(connection_failures)

                if latencies:
                    metrics['icmp']['lat_avg'].labels(**label_values).set(sum(latencies) / len(latencies))
                    metrics['icmp']['lat_min'].labels(**label_values).set(min(latencies))
                    metrics['icmp']['lat_max'].labels(**label_values).set(max(latencies))
                    if len(latencies) > 1:
                        metrics['icmp']['lat_jitter'].labels(**label_values).set(statistics.stdev(latencies))
                    else:  # len(latencies) == 1
                        metrics['icmp']['lat_jitter'].labels(**label_values).set(0)
                    for lat in latencies:
                        metrics['icmp']['lat_histogram'].labels(**label_values).observe(lat)
                    metrics['icmp']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                else:
                    for m in ['lat_avg', 'lat_min', 'lat_max', 'lat_jitter']:
                        metrics['icmp'][m].labels(**label_values).set(-1)
                    metrics['icmp']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                metrics['icmp']['pkt_loss'].labels(**label_values).set(loss)
                metrics['icmp']['success'].labels(**label_values).set(success_rate)

            elif target.protocol == 'tcp':
                start = time.time()
                sock = None
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(target.timeout)
                    sock.connect((address, target.port))
                    latency = (time.time() - start) * 1000
                    metrics['tcp']['lat_avg'].labels(**label_values).set(latency)
                    metrics['tcp']['lat_histogram'].labels(**label_values).observe(latency)
                    metrics['tcp']['success'].labels(**label_values).set(1)
                    metrics['tcp']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except socket.timeout:
                    metrics['tcp']['lat_avg'].labels(**label_values).set(-1)
                    metrics['tcp']['success'].labels(**label_values).set(0)
                    metrics['tcp']['error_timeout_count'].labels(**label_values).inc()
                    metrics['tcp']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except socket.error as e:
                    metrics['tcp']['lat_avg'].labels(**label_values).set(-1)
                    metrics['tcp']['success'].labels(**label_values).set(0)
                    if 'Connection refused' in str(e):
                        metrics['tcp']['error_connection_refused_count'].labels(**label_values).inc()
                    metrics['tcp']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                finally:
                    if sock is not None:
                        sock.close()

            elif target.protocol == 'http':
                start = time.time()
                try:
                    resp = requests.get(f"http://{address}:{target.port}", timeout=target.timeout)
                    latency = (time.time() - start) * 1000
                    status_code = resp.status_code
                    is_success = 200 <= status_code < 400
                    metrics['http']['lat_avg'].labels(**label_values).set(latency)
                    metrics['http']['lat_histogram'].labels(**label_values).observe(latency)
                    metrics['http']['success'].labels(**label_values).set(1 if is_success else 0)
                    metrics['http']['response_code'].labels(**label_values).set(status_code)
                    if is_success:
                        metrics['http']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                    else:
                        metrics['http']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except requests.RequestException as e:
                    metrics['http']['lat_avg'].labels(**label_values).set(-1)
                    metrics['http']['success'].labels(**label_values).set(0)
                    if 'Connection refused' in str(e):
                        metrics['http']['error_connection_refused_count'].labels(**label_values).inc()
                    elif 'timed out' in str(e):
                        metrics['http']['error_timeout_count'].labels(**label_values).inc()
                    metrics['http']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)

            elif target.protocol == 'https':
                start = time.time()
                try:
                    resp = requests.get(f"https://{address}:{target.port}", timeout=target.timeout)
                    latency = (time.time() - start) * 1000
                    status_code = resp.status_code
                    is_success = 200 <= status_code < 400
                    metrics['https']['lat_avg'].labels(**label_values).set(latency)
                    metrics['https']['lat_histogram'].labels(**label_values).observe(latency)
                    metrics['https']['success'].labels(**label_values).set(1 if is_success else 0)
                    metrics['https']['response_code'].labels(**label_values).set(status_code)
                    if is_success:
                        metrics['https']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                    else:
                        metrics['https']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except requests.RequestException as e:
                    metrics['https']['lat_avg'].labels(**label_values).set(-1)
                    metrics['https']['success'].labels(**label_values).set(0)
                    metrics['https']['response_code'].labels(**label_values).set(0)
                    if 'Connection refused' in str(e):
                        metrics['https']['error_connection_refused_count'].labels(**label_values).inc()
                    elif 'timed out' in str(e):
                        metrics['https']['error_timeout_count'].labels(**label_values).inc()
                    metrics['https']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)

            elif target.protocol == 'dns':
                try:
                    latency = probe_dns_lookup(address, target.timeout, target.dns_server, target.dns_port)
                    metrics['dns']['lat_avg'].labels(**label_values).set(latency)
                    metrics['dns']['lat_histogram'].labels(**label_values).observe(latency)
                    metrics['dns']['success'].labels(**label_values).set(1)
                    metrics['dns']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except dns.exception.Timeout:
                    metrics['dns']['lat_avg'].labels(**label_values).set(-1)
                    metrics['dns']['success'].labels(**label_values).set(0)
                    metrics['dns']['error_timeout_count'].labels(**label_values).inc()
                    metrics['dns']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except dns.exception.DNSException:
                    metrics['dns']['lat_avg'].labels(**label_values).set(-1)
                    metrics['dns']['success'].labels(**label_values).set(0)
                    metrics['dns']['error_connection_refused_count'].labels(**label_values).inc()
                    metrics['dns']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)

            elif target.protocol == 'udp':
                start = time.time()
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(target.timeout)
                    sock.sendto(b'test', (address, target.port))
                    # UDP probe semantics here represent local send-path success, not remote service health.
                    latency = (time.time() - start) * 1000
                    sock.close()
                    metrics['udp']['lat_avg'].labels(**label_values).set(latency)
                    metrics['udp']['lat_histogram'].labels(**label_values).observe(latency)
                    metrics['udp']['success'].labels(**label_values).set(1)
                    metrics['udp']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except socket.timeout:
                    metrics['udp']['lat_avg'].labels(**label_values).set(-1)
                    metrics['udp']['success'].labels(**label_values).set(0)
                    metrics['udp']['error_timeout_count'].labels(**label_values).inc()
                    metrics['udp']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except socket.error as e:
                    metrics['udp']['lat_avg'].labels(**label_values).set(-1)
                    metrics['udp']['success'].labels(**label_values).set(0)
                    if 'Connection refused' in str(e) or 'unreachable' in str(e):
                        metrics['udp']['error_connection_refused_count'].labels(**label_values).inc()
                    metrics['udp']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)

            elif target.protocol == 'ntp':
                try:
                    start = time.time()
                    client = ntplib.NTPClient()
                    response = client.request(address, version=target.ntp_version, timeout=target.timeout)
                    latency = response.delay * 1000 if response.delay is not None else (time.time() - start) * 1000
                    # Fallback if negative (clock skew or measurement artifact)
                    if latency < 0:
                        latency = (time.time() - start) * 1000
                    # Final sanity check
                    if latency < 0:
                        logging.warning(f"NTP latency is negative for {address} (clock skew?): {latency}ms, clamping to 0")
                        latency = 0
                    elif latency > 10000:
                        logging.warning(f"NTP latency unusually high for {address}: {latency}ms")
                    metrics['ntp']['lat_avg'].labels(**label_values).set(latency)
                    metrics['ntp']['lat_histogram'].labels(**label_values).observe(latency)
                    metrics['ntp']['success'].labels(**label_values).set(1)
                    metrics['ntp']['uptime_seconds'].labels(**label_values).inc(PING_INTERVAL)
                except Exception as e:
                    metrics['ntp']['lat_avg'].labels(**label_values).set(-1)
                    metrics['ntp']['success'].labels(**label_values).set(0)
                    if 'timed out' in str(e):
                        metrics['ntp']['error_timeout_count'].labels(**label_values).inc()
                    else:
                        metrics['ntp']['error_connection_refused_count'].labels(**label_values).inc()
                    metrics['ntp']['downtime_seconds'].labels(**label_values).inc(PING_INTERVAL)

            else:
                logging.warning(f"Unsupported protocol: {target.protocol} for {address}")

        except Exception as e:
            logging.error(f"Error checking {address}: {e}")
            if target.protocol == 'icmp':
                for m in ['lat_avg', 'lat_min', 'lat_max', 'lat_jitter', 'success']:
                    metrics['icmp'][m].labels(**label_values).set(-1)
                metrics['icmp']['pkt_loss'].labels(**label_values).set(100)
            else:
                for m in ['lat_avg', 'success']:
                    metrics[target.protocol][m].labels(**label_values).set(-1)

        stop_event.wait(PING_INTERVAL)

if __name__ == "__main__":
    start_http_server(EXPORTER_PORT)
    logging.info(f"Exporter running at http://localhost:{EXPORTER_PORT}/metrics")
    update_targets()

    observer = Observer()
    observer.schedule(ConfigWatcher(), '.', recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        observer.stop()
        observer.join()
        with targets_lock:
            for key, stop_event in thread_stoppers.items():
                stop_event.set()
            for key, thread in active_threads.items():
                thread.join()
