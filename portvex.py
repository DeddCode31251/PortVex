"""

PortVex is a command-line network reconnaissance tool written in Python.
Made by: Deadcode
Github: https://github.com/DeddCode31251/PortVex
Only Scan Systems you own or are explicitly authorised to test.

"""

# #~[Libraries]~#
import argparse
import time
import ipaddress
import socket
import json
import sys
import asyncio
import errno
import os
import re
import ssl
import csv


from dataclasses import asdict, dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

__version__ = "2.1.0"

# #~[Static Data]~#
SERVICE_MAP = {
    20: 'ftp-data',
    21: 'ftp',
    22: 'ssh',
    23: 'telnet',
    25: 'smtp',
    53: 'dns',
    69: 'tftp',
    80: 'http',
    81: 'http',
    88: 'kerberos',
    110: 'pop3',
    111: 'rpcbind',
    113: 'ident',
    119: 'nntp',
    123: 'ntp',
    135: 'msrpc',
    139: 'netbios-ssn',
    143: 'imap',
    161: 'snmp',
    179: 'bgp',
    389: 'ldap',
    443: 'https',
    445: 'smb',
    465: 'smtps',
    514: 'syslog',
    515: 'printer',
    587: 'submission',
    593: 'http-rpc',
    636: 'ldaps',
    873: 'rsync',
    902: 'vmware',
    993: 'imaps',
    995: 'pop3s',
    1080: 'socks',
    1099: 'rmi',
    1433: 'mssql',
    1521: 'oracle',
    1723: 'pptp',
    2049: 'nfs',
    2121: 'ftp-alt',
    2375: 'docker',
    2376: 'docker-tls',
    3000: 'http-dev',
    3128: 'squid',
    3306: 'mysql',
    3389: 'rdp',
    3690: 'svn',
    4369: 'epmd',
    4444: 'metasploit/shell',
    5000: 'http-dev',
    5432: 'postgresql',
    5601: 'kibana',
    5672: 'amqp',
    5900: 'vnc',
    5985: 'winrm',
    5986: 'winrm-tls',
    6379: 'redis',
    6443: 'kubernetes-api',
    7001: 'weblogic',
    8000: 'http-alt',
    8008: 'http-alt',
    8080: 'http-proxy',
    8081: 'http-alt',
    8443: 'https-alt',
    8500: 'consul',
    8888: 'http-alt',
    9000: 'http-alt',
    9090: 'http-alt',
    9092: 'kafka',
    9200: 'elasticsearch',
    9300: 'elasticsearch',
    9443: 'https-alt',
    10000: 'webmin',
    11211: 'memcached',
    27017: 'mongodb',
    50000: 'jenkins-agent',
}

# Common Ports List
COMMON_PORTS = sorted(SERVICE_MAP)

# HTTP Ports List
HTTP_PORTS = {80,81,3000,5000,5601,8000,8008,8080,8081,8888,9000,9090,9200,10000,2375}

# TLS Ports List
TLS_PORTS = {443,465,636,853,993,995,2376,5986,6443,8443,9443}

# Banner Signatures (regex on first line/ Whole text, service, version group)
SIGNATURES = [
    (re.compile(r"^SSH-\d\.\d+-(\S+)"), "ssh", 1),
    (re.compile(r"^220[ -].*\b(vsFTPd|ProFTPD|Pure-FTPd|FileZilla|Microsoft FTP)[^\r\n]*", re.I), "ftp", 0),
    (re.compile(r"^220[ -].*\b(ESMTP|SMTP|Postfix|Exim|Sendmail)\b[^\r\n]*", re.I), "smtp", 0),
    (re.compile(r"^220[ -][^\r\n]*FTP[^\r\n]*", re.I), "ftp", 0),
    (re.compile(r"^\+OK[^\r\n]*"), "pop3", 0),
    (re.compile(r"^\* OK[^\r\n]*IMAP[^\r\n]*", re.I), "imap", 0),
    (re.compile(r"^RFB (\d{3}\.\d{3})"), "vnc", 1),
    (re.compile(r"^\+PONG|^-NOAUTH|^-DENIED|^-ERR wrong number"), "redis", 0),
    (re.compile(r"^HTTP/\d(?:\.\d)? \d{3}"), "http", 0),
    (re.compile(r"^AMQP"), "amqp", 0),
    (re.compile(r"^-ERR|^\x00\x00"), "unknown", 0),
]

# Port-specific probes sent when the server stays silent 
PROBES = {
    6379: b"PING\r\n"
}
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHOST: %s\r\nUser-Agent: PortVex\r\n\r\n"
GENERIC_PROBE = b"\r\n"

# #~[Output Helpers]~#

class C:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    RED,GREEN,YELLOW,BLUE,CYAN,MAGENTA,ORANGE,DIM,BOLD,END = (
        ('\033[91m', '\033[92m', '\033[93m', '\033[94m',
        '\033[96m', '\033[95m', '\033[38;5;208m', '\033[2m', '\033[1m', '\033[0m') if on else ("",) * 10
    )

# Banner

Banner = rf"""{C.RED}

⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡄⣄⣴⣦⣤⣄⣤⡄⣀⣠⡄⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣂⣞⣿⣿⣿⣿⣿⣿⣿⣯⣿⣿⣿⣿⣿⣷⡐⣾⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣤⣀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣯⣿⣿⣿⣷⣷⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢼⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⡿⣿⣿⣿⣽⡿⠯⢿⣿⣿⣿⣿⣯⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣿⣿⣿⣿⡟⠓⠉⠁⠀⠀⠀⣠⣿⣿⣗⡡⡉⠐⠨⢻⣿⣿⣿⣯⣆⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠤⡻⢹⣿⣿⣿⣯⡀⠀⠀⠀⠀⢐⢹⣿⣿⣿⣿⡏⠂⠀⠀⠀⢿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣿⣿⣿⣿⣾⣿⣶⣶⣔⡨⣾⣷⣻⣿⣻⣺⡃⠀⠀⠀⠀⠀⢹⣿⣿⣿⠂⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠺⣿⣽⣿⣻⣿⣿⣿⣿⣿⣿⣿⣿⣶⣷⣿⣿⣷⣿⣷⣶⣦⣶⣸⣿⣿⣟⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⡙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⡿⣿⣷⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡻⣿⣳⣿⣿⣾⣿⣿⣿⣿⡟⠋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⠟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⠏⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠑⠙⠋⠏⠛⠛⠛⠓⠈⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
{C.BOLD} ___           _   __     __ 
| _ \___ _ _ _| |_ \ \   / /____ __
|  _/ _ \ '_|_  _|  \ \ / / -_) \ /
|_| \___/_|   |_|    \_/ \___/_\_\  v{__version__}
 {C.END}{C.YELLOW} async TCP recon - use only on authorised
 targets{C.END}
"""

PROGRESS_ACTIVE = False

def emit(msg: str) -> None:
    """ Print a line without colliding with the in-place progress line."""
    if PROGRESS_ACTIVE:
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()
    print(msg, flush=True)

# #~[Data Model]~#
@dataclass
class PortResult:
    port: int
    protocol: str
    state: str # open | closed | filtered | open/filtered
    service: str = ""
    banner: str = ""
    tls: str = "" # e.g. "TLSv1.3"
    rtt_ms: float = 0.0

class ScanState:
    """Shared mutable state so CTRL+C can still report partial results."""

    def __init__(self, ports: list[int]):
        self.ports = ports
        self.port_iter = iter(ports)
        self.done = 0
        self.open: list[PortResult] = []
        self.closed = 0
        self.filtered = 0
        self.started = time.monotonic()
        self.interrupted = False

# #~[Argument parsing helpers]~#
def parse_ports(spec: str) -> list[int]:
    """ '22,80,8000-8100' -> sorted unique list, '-' or 'all' -> 1-65535 """
    spec = spec.strip().lower()
    if spec in ('-', 'all'):
        return list(range(1,65536))
    ports: set[int] = set()
    for part in spec.split(','):
        part = part.strip()
        if not part:
            continue
        try:
            if '-' in part:
                lo_s, hi_s = part.split('-', 1)
                lo, hi = int(lo_s), int(hi_s)
            else:
                lo = hi = int(part)
        except ValueError:
            raise argparse.ArgumentTypeError(f"invalid port or range: '{part}'")
        if not (1 <= lo <= hi <= 65535):
            raise argparse.ArgumentTypeError(f"Port out of range (1-65535): '{part}'")
        ports.update(range(lo, hi+1))
    if not ports:
        raise argparse.ArgumentTypeError('no ports given')
    return sorted(ports)

def build_parser () -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portvex",
        description="PortVex - async TCP port scanner with service/banner detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "   portvex.py -i 10.10.10.5 --mode common\n"
            "   portvex.py -i 10.10.10.5 -p 20,80,8000-8100\n"
            "   portvex.py -i target.htb --mode full -w 1000 -t 1\n"
            "   portvex.py -i 10.10.10.5 --mode full -q | cut -d: -f2 | paste -sd,\n"
            ""
        ),
    )

    p.add_argument("-i", "--ip", required=True, help="target IPv4/IPv6 address or hostname")
    p.add_argument("-p", "--port", type=parse_ports, help="ports: 80 | 22,80,443 | 1-1024 | 22,8000-8100 | - (all)")
    p.add_argument("--mode", choices=["current","common","full"], default=None,
    help= "current = only -p, common=built-in list, full = 1-65535")
    p.add_argument("-t", "--timeout", type=float, default=1.5,
    help="connect timeout in seconds(default 1.5)")
    p.add_argument('-w', '--workers',type=int, default=500,
    help="max concurrent connections (default 500)")
    p.add_argument('-r', '--retries', type=int, default=1,
    help="retries for time-out ports (default 1)")
    p.add_argument('--rate', type=float, default=0, 
    help="max new connections per second (0 = unlimited)")
    p.add_argument('--no-banner', action="store_true", 
    help="skip banner grabbing/service detection (faster)")
    p.add_argument('-q', '--quiet', action='store_true',
    help="print only 'host:port' per open port (pipe-friendly, implies --no-banner)")
    p.add_argument('--txt', metavar="FILE", 
    help="export report as text")
    p.add_argument('--json',metavar="FILE", help="export report as JSON")
    p.add_argument('--version', action="version", version=f"PortVex {__version__}")
    p.add_argument('--csv', metavar="FILE", help="export scan results as CSV")
    p.add_argument('--scan-type', choices=['tcp','udp','both'], default='tcp', help="Scan type: tcp,udp,both")
    
    return p

class RateLimiter:
    """Spaces connection attemmpts evenly (N per second)"""

    def __init__(self, rate: float):
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()
    
    async def wait(self) -> None:
        if not self.interval:
            return
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            delay = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.interval
        
        if delay:
            await asyncio.sleep(delay)


async def _close(writer: asyncio.StreamWriter) -> None:
    try:
        writer.close()
        await asyncio.wait_for(writer.wait_closed(), 1.0)
    except Exception:
        pass
async def probe_tcp(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    limiter: RateLimiter
) -> PortResult:
    """
    TCP Connect Scan.

    States:
        open     = TCP connection succeeded.
        closed   = Connection refused.
        filtered = Timeout or another network error.
    """

    loop = asyncio.get_running_loop()
    state = "filtered"

    for attempt in range(retries + 1):

        # Respect the configured scan rate.
        await limiter.wait()

        start = loop.time()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )

            # Calculate response time.
            rtt = (loop.time() - start) * 1000

            # Connection succeeded, so the port is open.
            await _close(writer)

            return PortResult(
                port=port,
                protocol="tcp",
                state="open",
                rtt_ms=round(rtt, 1)
            )

        except (asyncio.TimeoutError, TimeoutError):
            # No response before timeout.
            state = "filtered"

        except ConnectionRefusedError:
            # The target actively refused the connection.
            return PortResult(
                port=port,
                protocol="tcp",
                state="closed"
            )

        except OSError as err:

            # File descriptor limit reached.
            if err.errno in (errno.EMFILE, errno.ENFILE):
                await asyncio.sleep(0.2)
                continue

            # Connection refused.
            if err.errno == errno.ECONNREFUSED:
                return PortResult(
                    port=port,
                    protocol="tcp",
                    state="closed"
                )

            # Other network errors.
            state = "filtered"
            break

    return PortResult(
        port=port,
        protocol="tcp",
        state=state
    )

async def probe_udp(
    host: str,
    port: int,
    timeout: float,
    retries: int,
    limiter: RateLimiter,
    payload: bytes = b""
) -> PortResult:
    """
    UDP Scan.

    States:
        open          = Received a UDP response.
        closed        = Received a connection-refused error,
                        commonly caused by ICMP port unreachable.
        open|filtered = No response before timeout.
        filtered      = Another network error.
    """

    loop = asyncio.get_running_loop()

    family = (
        socket.AF_INET6 if ":" in host
        else socket.AF_INET
    )

    state = "open|filtered"

    for attempt in range(retries + 1):

        await limiter.wait()

        sock = None
        start = loop.time()

        try:
            # Create a UDP socket.
            sock = socket.socket(
                family,
                socket.SOCK_DGRAM,
                socket.IPPROTO_UDP
            )

            sock.setblocking(False)

            # Associate the socket with the target.
            sock.connect((host, port))

            # Send our UDP probe.
            sock.send(payload)

            # Wait for a response.
            data = await asyncio.wait_for(
                loop.sock_recv(sock, 4096),
                timeout=timeout
            )

            rtt = (loop.time() - start) * 1000

            return PortResult(
                port=port,
                protocol="udp",
                state="open",
                banner=_clean(data)[:120],
                rtt_ms=round(rtt, 1)
            )

        except (asyncio.TimeoutError, TimeoutError):

            # UDP is connectionless.
            # Silence does not prove the port is closed.
            state = "open|filtered"

        except ConnectionRefusedError:

            # Commonly indicates ICMP port unreachable.
            return PortResult(
                port=port,
                protocol="udp",
                state="closed"
            )

        except OSError as err:

            if err.errno == errno.ECONNREFUSED:
                return PortResult(
                    port=port,
                    protocol="udp",
                    state="closed"
                )

            state = "filtered"
            break

        finally:

            # Always close the socket.
            if sock is not None:
                sock.close()

    return PortResult(
        port=port,
        protocol="udp",
        state=state
    )

async def probe_port(host: str, port: int, timeout: float, retries: int, limiter: RateLimiter) -> PortResult:
    """TCP connect check. Distinguishes open / closed (RST) / filtered (silence)."""
    loop = asyncio.get_running_loop()
    state = "filtered"
    for attempt in range(retries + 1):
        await limiter.wait()
        t0 = loop.time()
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
            rtt = (loop.time() - t0) * 1000
            await _close(writer)
            return PortResult(port, "open", rtt_ms=round(rtt, 1))
        except (asyncio.TimeoutError, TimeoutError):
            state = "filtered" # No answer: retry, could be packet loss
            continue
        except ConnectionRefusedError:
            return PortResult(port, "closed") # RST: host is up, port is closed
        except OSError as e:
            if e.errno in (errno.EMFILE, errno.ENFILE):
                await asyncio.sleep(0.2) # out of file descriptors: back off, retry
                continue
            state = "filtered"
            break
    return PortResult(port, state)

async def _talk(host: str, sni: str | None, port: int, use_tls: bool, passive: bool, probe:bytes | None, timeout: float):
    """ Open a connection, optionally wrap in TLS, read a banner. returns (data, tls_version) """
    ctx = None
    if use_tls: 
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE # recon: we want to see self-signed certs too
        
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0") # allow old servers
        except ssl.SSLError:
            pass
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni if use_tls else None),
        timeout,
    )
    tls_version=""
    try: 
        if use_tls:
            sslobj = writer.get_extra_info("ssl_object")
            tls_version = sslobj.version() if sslobj else ""
        data=b""
        read_to = min(timeout, 1.5)
        if passive: # many services (ssh/ftp/smtp) talk first
            try: 
                data = await asyncio.wait_for(reader.read(1024), read_to)
            except (asyncio.TimeoutError, TimeoutError):
                data=b""
        if not data and probe: # silent: poke it
            writer.write(probe)
            await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(2048), read_to)
            except (asyncio.TimeoutError, TimeoutError):
                data=b""
        return data, tls_version
    finally:
        await _close(writer)

def _clean(data: bytes) -> str:
    text = data.decode("utf-8", "replace")
    return "".join(ch if ch.isprintable() or ch in "\r\n\t" else "." for ch in text)

def identify(port: int, data:bytes, tls:str) -> tuple[str,str]:
    """ Return (service, banner), Service ends in '?' when it is only a port-number guess."""
    text = _clean(data).strip()

    # Mysql greeting: 3-byte length, seq, protocol 0x0a, then NUL-terminated version
    if len(data) > 6 and data[4] == 0x0A and data[5:6].isdigit():
        ver=data[5:].split(b"\x00", 1)[0].decode("latin-1", 'replace')
        return 'mysql',ver
    
    for rx, service, grp in SIGNATURES:
        m = rx.search(text)
        if not m or service == "unknown":
            continue
        if service == "http":
            server = re.search(r"^Server:\s*(.+)$", text, re.I | re.M)
            status = text.splitlines()[0][:60]
            banner = f"{status} | {server.group(1).strip()}" if server else status
            if tls:
                service = "https"
            return service, banner[:120]
        if grp:
            return service,m.group(grp)[:120]
        return service, (text.splitlines()[0] if text else  "")[:120]
    guess = SERVICE_MAP.get(port)
    first_line = text.splitlines()[0][:120] if text else ""
    if guess:
        return guess + "?", first_line
    return "unknown", first_line        

async def fingerprint(host: str, sni:str | None, port:int, timeout: float) -> tuple[str, str, str]:
    """ Grab banner and work out the service. Returns (service, banner, tls_version)"""
    host_hdr = (sni or host).encode()
    http_probe = HTTP_PROBE % host_hdr
    is_http = port in HTTP_PORTS or port in (443, 8443, 9443, 6443)
    plain_probe = http_probe if is_http else PROBES.get(port, GENERIC_PROBE)

    async def attempt(use_tls: bool):
        probe = http_probe if (use_tls and is_http) or (use_tls and port not in TLS_PORTS) \
            else (plain_probe if not use_tls else GENERIC_PROBE)
        passive = not (is_http and not use_tls)
        return await _talk(host, sni, port, use_tls, passive,probe, timeout)

    order = [True,False] if port in TLS_PORTS else [False, True]
    for use_tls in order:
        try:
            data, tls = await attempt(use_tls)
        except (ssl.SSLError, ConnectionError, OSError, asyncio.TimeoutError, TimeoutError):
            continue

        # Plain attempt that got nothing, or a TLS alert: the port is probably TLS
        if not use_tls and (not data or data[:2] in (b"\x15\03", b"\x16\x03")):
            continue
        service, banner = identify(port, data, tls)
        if tls and not service.endswith("?") and service not in ("https",):
            service += "/tls"
        elif tls and service.endswith("?") and not service.startswith("http"):
            service = service[:-1] + "/tls?"
        return service, banner, tls

    # Nothinhg workerd: fall back to port-number guess
    guess = SERVICE_MAP.get(port)
    return (guess + "?" if guess else "unknown"), "", ""

async def run_tcp_scan(host: str, ports: list[int],args, state: ScanState) -> None:
    """ TCP only Scan """

    global PROGRESS_ACTIVE

    limiter = RateLimiter(args.rate)
    total = len(ports)

    if total == 0:
        return
    
    tty_progress = (
        sys.stderr.isatty()
        and not args.quiet
        and total > 200
    )

    # Workers: Scans ports one by one
    async def worker():
        while True:
            try:
                port = next(state.port_iter) # atomic in asyncio: no locks needed
            except StopIteration:
                return
            # Probe this TCP port.
            res = await probe_tcp(
                host,
                port,
                args.timeout,
                args.retries,
                limiter
            )

            state.done += 1

            # Process the result
            if res.state == "open":
                state.open.append(res)

                if args.quiet:
                    emit(f"{args.ip}:{port}")

                else: 
                    emit(
                        f"{C.GREEN}{C.BOLD}[+]{C.END} "
                        f"{C.BOLD}{C.CYAN}{port}/tcp{C.END} "
                        f"{C.GREEN}open{C.END} "
                        f"{C.DIM}({res.rtt_ms} ms){C.END}"
                    )
            elif res.state == "closed":
                state.closed += 1
            else:
                state.filtered += 1
            
    # Progress Display
    async def progress():
        global PROGRESS_ACTIVE
        PROGRESS_ACTIVE = True
        try:
            while state.done < total:
                await asyncio.sleep(0.4)
                percentage = state.done * 100 // total
                sys.stderr.write(
                    f"\r\033[K"
                    f"{C.YELLOW}[~]{C.END}"
                    f"{C.DIM} {state.done}/{total} ports "
                    f"({percentage}%)"
                    f"- {len(state.open)} open{C.END}"
                )
                sys.stderr.flush()
        finally:
            sys.stderr.write("\r\033[K")
            sys.stderr.flush()
            PROGRESS_ACTIVE = False
    
    # Start concurrent workers
    worker_count = max(1, min(args.workers, total))
    
    progress_task = (
        asyncio.create_task(progress())
        if tty_progress
        else None
    )

    try:
        await asyncio.gather(
            *(worker() for _ in range(worker_count))
        )
    finally:
        if progress_task:
            progress_task.cancel()

            try:
                await progress_task
            except asyncio.CancelledError:
                pass
    
    # Fingerprint open TCP ports

    if state.open and not args.no_banner and not args.quiet:
        sni = None if _is_ip(args.ip) else args.ip
        semaphore = asyncio.Semaphore(50)
        
        async def fingerprint_worker(res: PortResult):
            async with semaphore:
                try:
                    (
                        res.service,
                        res.banner,
                        res.tls
                    ) = await fingerprint(
                        host,
                        sni,
                        res.port,
                        max(
                            args.timeout, 2.0
                        )
                    )
                except Exception:
                    res.service = (
                        SERVICE_MAP.get(res.port, "unknown") + "?"
                    )
        print(
            f"{C.BLUE}[*]{C.END} "
            f"{C.DIM}Fingerprinting"
            f"{len(state.open)} open TCP port(s)...{C.END}"
        )

        await asyncio.gather(
            *(fingerprint_worker(res) for res in state.open) 
        )
    else:

        # Basic service-name guesses when fingerprinting is disabled
        for res in state.open:
            res.service = (
                SERVICE_MAP.get(res.port, "unknown") + "?"
            )



async def run_udp_scan(
    host: str,
    ports: list[int],
    args,
    state: ScanState
) -> None:
    """ UDP only Scan (asynchronous UDP)"""
    limiter = RateLimiter(args.rate)
    
    async def worker():
        while True:
            port = next(state.port_iter, None)

            if port is None:
                return

            # Probe this UDP port.
            res = await probe_udp(
                host,
                port,
                args.timeout,
                args.retries,
                limiter
            )

            state.done += 1

            if res.state == "open":
                state.open.append(res)

            elif res.state == "closed":
                state.closed += 1
            
            elif res.state == "open|filtered":
                state.filtered += 1
            
            else:
                state.filtered += 1
    
    # Start Workers
    workers = [
        asyncio.create_task(worker())
        for _ in range(min(args.workers, len(ports)))
    ] 

    try: 
        await asyncio.gather(*workers)

    except asyncio.CancelledError:
        state.interrupted = True
        raise
    
    # Sort results by port.
    state.open.sort(key=lambda result: result.port)

async def run_scan(host: str, ports: list[int], args, state: ScanState) -> None:
    if args.scan_type == "tcp":
        await run_tcp_scan(host, ports, args, state)

    elif args.scan_type == "udp":
        await run_udp_scan(host, ports, args, state)

    elif args.scan_type == "both":
        await run_tcp_scan(host, ports, args, state)

        # Reset the iterator for UDP
        state.port_iter = iter(ports)a
        state.done = 0

        await run_udp_scan(host, ports, args, state)
    


# #~[Target handling & reporting]~#

def _is_ip(value:str) -> bool:
    for fam in ((socket.AF_INET, socket.AF_INET6)):
        try:
            socket.inet_pton(fam, value)
            return True
        except OSError:
            pass
    return False

async def resolve(target: str) -> str:
    if _is_ip(target):
        return target
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    return infos[0][4][0]

def fd_limit_cap(requested: int) -> int:
    """ Dont ask for more sockets than the OS Allows (Linux/macOS) """
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        want = min(hard, 65535) if hard != resource.RLIM_INFINITY else 65535

        if soft < want:
            try: 
                resource.setrlimit(resource.RLIMIT_NOFILE, (want, hard))
                soft = want
            except (ValueError, OSError):
                pass
        return max(1, min(requested, soft - 64))
    except ImportError:
        return min(requested, 500) # Windoes: select() limits

# Services that are commonly attacked / misconfigured -> shown in red
RISKY_SERVICES = {
    'telnet','ftp','ftp-data','ftp-alt','tftp','smb','netbios-ssn','msrpc','rpcbind','nfs',
    'rdp','vnc','snmp','redis','mongodb','memcached','docker','mssql','mysql','postgresql',
    'elasticsearch','rsync','metasploit','kibana','rmi','weblogic','consul',
}

def service_color(service: str) -> str:
    """ red = risky, green = encrypted/standard, yellow = web, magenta = unknown, cyan = other """
    base = service.rstrip("?").split("/")[0]
    if base == "unknown":
        return C.MAGENTA
    if base in RISKY_SERVICES:
        return C.RED
    if base.startswith("https") or base in ("ssh", "ldaps", "smtps", "imaps", "pop3s"):
        return C.GREEN
    if base.startswith("http"):
        return C.YELLOW
    return C.CYAN

def render_table(state: ScanState, color: bool = False) -> list[str]:
    rows = sorted(state.open, key=lambda r: r.port)
    head = f"{'PORT': <10}{'STATE': <8}{'SERVICE': <16}INFO"
    lines = [f"{C.BOLD}{head}{C.END}" if color else head]
    for r in rows:
        info = r.banner
        if r.tls:
            info = f"[{r.tls}] {info}".strip()
        port_s = f"{str(r.port) + '/tcp':<10}"
        state_s = f"{r.state: <8}"
        serv_s = f"{r.service:<16}"
        if color: # pad first, colour after, so columns stay aligned
            port_s = f"{C.BOLD}{C.CYAN}{port_s}{C.END}"
            state_s = f"{C.GREEN}{state_s}{C.END}"
            serv_s = f"{service_color(r.service)}{serv_s}{C.END}"
            if r.tls:
                info = f"{C.MAGENTA}[{r.tls}]{C.END} {r.banner}".strip()
        lines.append(f"{port_s}{state_s}{serv_s}{info}")
    return lines

def write_reports(args, ip: str, state: ScanState, started:datetime, duration: float) -> None:
    summary = {"scanned": state.done, "open": len(state.open), "closed": state.closed, "filtered": state.filtered}
    if args.txt:
        with open(args.txt, 'w', encoding="utf-8") as f:
            f.write(f"PortVex {__version__} report\n")
            f.write(f"Target: {args.ip} ({ip})\nStarted: {started.isoformat()}\n")
            f.write(f"Time  : {duration:.2f}s\n")
            f.write(f"Summary: {summary}\n\n")
            f.write("\n".join(render_table(state)) + "\n")
        if not args.quiet:
            print(f"{C.GREEN}[*]{C.END} TXT report saved to {args.txt}")

    if args.json:
        doc = {
            "tool": "PortVex","version": __version__,
            "target": {"input": args.ip, "ip": ip},
            "started": started.isoformat(),"duration_s": round(duration, 2), "interrupted": state.interrupted,
            "options": {"timeout": args.timeout,"workers":args.workers, "retries": args.retries,"rate": args.rate},
            "summary": summary,
            "results": [asdict(r) for r in sorted(state.open, key=lambda r: r.port)],
        }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(doc, f,indent=2)
        if not args.quiet:
            print(f"{C.GREEN}[*]{C.END} JSON report saved to {args.json}")
    if args.csv:
        fieldnames = [
            "target",
            "resolved_ip",
            "port",
            "protocol",
            "state",
            "service",
            "banner",
            "tls"
            "rtt_ms"
        ]

        try:
            with open(args.csv, 'w',newline="",encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=fieldnames
                )

                # Write CSV column names
                writer.writeheader()

                # Write each open port
                for result in sorted(
                    state.open,
                    key=lambda r:r.port
                ):
                    writer.writerow({
                        "target": args.ip,
                        "resolved_ip": ip,
                        "port": result.port,
                        "protocol": "tcp",
                        "state": result.state,
                        "service": result.service,
                        "banner": result.banner,
                        "tls": result.tls,
                        "rtt_ms": result.rtt_ms
                    })

            if not args.quiet:
                print(
                    f"{C.GREEN}[*]{C.END} "
                    f"CSV report saved to {args.csv}"
                )

        except OSError as error:
            print(
                f"{C.RED}[x]{C.END} "
                f"Failed to export CSV: {error}",
                file=sys.stderr
            )
# #~[Entry Point]~#
def selected_ports(args, parser) -> list[int]:
    mode = args.mode
    if mode is None: 
        mode = "current" if args.port else "common"
    if mode == "current":
        if not args.port:
            parser.error("--mode current requires -p/--port")
        return args.port
    if args.port and mode in ("common", "full"):
        print(f"{C.YELLOW}[!]{C.END} -p ignored because --mode {mode} was given", file=sys.stderr)
    return COMMON_PORTS if mode == "common" else list(range(1,65536))

async def amain(args, ports: list[int], state: ScanState) -> str:
    ip = await resolve(args.ip)
    if not args.quiet:
        print(f"{C.BLUE}[*]{C.END} Target : {C.BOLD}{C.CYAN}{args.ip}{C.END}" + (f"({ip})" if ip != args.ip else ""))
        print(f"{C.BLUE}[*]{C.END} Ports : {len(ports)} workers={args.workers} "
        f"timeout={args.timeout}s retries={args.retries}" + (f" rate={args.rate}/s" if args.rate else ""))
    await run_scan(ip, ports, args,state)
    return ip

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if args.timeout <=0 or args.workers < 1 or args.retries < 0:
        parser.error("timeout must be > 0, workers >= 1, retries >= 0")
    ports = selected_ports(args, parser)
    args.workers = fd_limit_cap(args.workers)

    if not args.quiet:
        print(Banner)
    state = ScanState(ports)
    started = datetime.now(timezone.utc)
    ip = args.ip
    try: 
        ip = asyncio.run(amain(args, ports, state))
    except KeyboardInterrupt:
        state.interrupted = True
        print(f"\n{C.RED}[!]{C.END} Interrupted - showing partial results", file=sys.stderr)
    except socket.gaierror as e:
        print(f"{C.RED}[x]{C.END} Cannot resolve '{args.ip}': {e}",file=sys.stderr)
        return 2
    
    duration = time.monotonic() - state.started

    write_reports(args, ip, state, started, duration)

    if args.quiet:
        return 0

    print()

    if state.open:
        print("\n".join(render_table(state, color=True)))
    else:
        print(f"{C.RED}[-]{C.END} {C.RED}No open ports found.{C.END}")
    print(f"\n{C.BOLD} Scanned {state.done}/{len(ports)} ports in {duration:.2f}s{C.END} "
            f"{C.GREEN}open={len(state.open)}{C.END} {C.DIM}closed={state.closed}{C.END} {C.ORANGE}filtered={state.filtered}{C.END}")
    
    if state.filtered > state.closed and state.filtered > 100:
        print(f"{C.ORANGE}[i] Most ports are filtered -> a firewall is probably dropping packets.{C.END}")

    
    return 0
 
if __name__ == "__main__":
    sys.exit(main())
    
""" Old version
# #~[Functions]~#

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="PortVex - Network Reconnaissance Tool"
    )

    parser.add_argument(
        "-i",
        "--ip",
        required=True,
        help="Target IP address"
    )

    parser.add_argument(
        "-p",
        "--port",
        type=int,
        help="Single TCP port (current mode)"
    )

    parser.add_argument(
        "--mode",
        choices=["current","common","full"],
        default="common",
        help="Scanning mode"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent workers (default: 100)"
    )

    parser.add_argument(
        "--json",
        metavar="FILE",
        help="Export results as JSON file"
    )

    parser.add_argument(
        "--txt",
        metavar="FILE",
        help="Export results as TXT file"
    )

    args = parser.parse_args()

    # Validate IP
    try:
        ipaddress.ip_address(args.ip)
    except ValueError:
        parser.error("Invalid IP address.")
    
    # Validate PORT
    if args.mode == "current":
        if args.port is None:
            parser.error("Current mode requires -p.")
        if not 1 <= args.port <= 65535:
            parser.error("Port must be between 1 and 65535.")
    elif args.port is not None:
        parser.error("-p can only be used with current mode.")
    if args.timeout <= 0:
        parser.error("Timeout must be greater than zero.")
    if args.workers < 1 or args.workers > 500:
        parser.error("Workers must be between 1 and 500.")
    
    return args

# Port Selection function
def get_ports(mode, port=None):
    
    if mode == "current":
        return [port]
    
    elif mode=="common":
        return COMMON_PORTS.copy()
    
    elif mode =="full":
        return list(range(1,65536))
    return []

# Identify service function
def identify_service(port):
    try: 
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "Unknown"

# Progess Bar
def show_progress(completed, total, width=35):
    if total == 0:
        return
    
    percentage = completed/total
    filled = int(width * percentage)
    bar = "#" * filled + '-' * (width - filled)

    sys.stdout.write(
        f"\r{Colors.CYAN}"
        f"[{bar}]"
        f"{percentage * 100:5.1f}%"
        f" | {completed}/{total} ports"
        f"{Colors.RESET}"
    )

    sys.stdout.flush()
# Scan port Function
def scan_port(ip, port, timeout):

    result = {
        "port": port,
        "state": "closed/filtered",
        "service": identify_service(port),
        "error": None
    }

    try:
        with socket.create_connection(
            (ip, port),
            timeout=timeout
        ):

            result["state"] = "open"
    except ConnectionRefusedError:
        result["state"] = "closed"

    except socket.timeout:
        result["state"] = "filtered/timeout"
    
    except OSError as error:
        result["state"] = "error"
        result["error"] = str(error)
    
    return result

# Scanning Engine function
def display_summary(ip, mode, results, duration):
    
    open_ports = [
        result for result in results
        if result["state"] == "open"
    ]

    closed_ports = [
        result for result in results
        if result["state"] == "closed"
    ]

    filtered_ports = [
        result for result in results
        if result["state"] == "filtered/timeout"
    ]

    error_ports = [
        result for result in results
        if result['state'] == "error"
    ]

    print_section("SCAN SUMMARY")
    print(f"Target IP: {ip}")
    print(f"Scan Mode: {mode.upper()}")
    
    print(f"Total scanned: {len(results)}")
    print(f"Open ports: {len(open_ports)}")
    print(f"Closed ports: {len(closed_ports)}")
    print(f"Filtered ports: {len(filtered_ports)}")
    print(f"Errors: {len(error_ports)}")

    print(f"Duration: {duration:.2f} seconds")
    print_section("OPEN PORTS")

    if open_ports:
        for result in open_ports:
            print(
                f"{result['port']:<8}"
                f"{result['service']}"
            )
    else:
        print_warning('No open ports discovered.')
    
    print("\n" + "*" *10)

# TXT Export function
def export_txt(filename, ip,mode, results,duration):
    open_ports = [r for r in results if r['state'] == 'open']
    closed_ports = [r for r in results if r['state'] == 'closed']
    filtered_ports = [r for r in results if r['state'] == 'filtered/timeout']
    error_ports = [r for r in results if r['state'] == 'error']

    report = { 
        "tool": "PortVex",
        "version": VERSION,
        
        "target": ip,
        "mode": mode,

        "timestamp": datetime.now().isoformat(),
        "duration": round(duration, 3),
        "total_ports": len(results),
        "results": results
    }

    try: 
        with open(filename, 'w', encoding='utf-8') as file:
            file.write("*"*10+"\n")
            file.write("PORTVEX SCAN REPORT\n")
            file.write("*"*10+"\n")

            file.write("[ SCAN INFORMATION ]\n")
            file.write("-" * 10 + "\n")

            # General Information
            file.write(f"Tool: {report['tool']}\n")
            file.write(f"Version: {report['version']}\n")
            file.write(f"Target: {report['target']}\n")
            file.write(f"Mode: {report['mode']}\n")
            file.write(f"Timestamp: {report['timestamp']}\n")
            file.write(f"Duration: {report['duration']} seconds \n")
            file.write(f"Total ports: {report['total_ports']} \n\n")

            # Statistics
            file.write("[ SCAN STATISTICS ]\n")
            file.write("*" * 10 + '\n')
            file.write(f"Open ports: {len(open_ports)}\n")
            file.write(f"Closed ports: {len(closed_ports)}\n")
            file.write(f"Filtered ports: {len(filtered_ports)}\n")
            file.write(f"Errors: {len(error_ports)}\n\n")

            # Port results
            file.write("[ PORT RESULTS ]\n")
            file.write("-" * 10 + "\n")

            if results:
                file.write(f"{'PORT':<12}{'SERVICE':<20}{'STATE'}\n")
                file.write('-'*10+ '\n')
                
                for result in results:
                    file.write(
                        f"{result['port']:<12}"
                        f"{result['service']:<20}"
                        f"{result['state'].upper()}\n"
                    )
            else:
                file.write("No scan results available.\n")
            file.write("*"*10 + "\n")
            file.write("END OF PORTVEX REPORT\n") 
            file.write( "*" * 10 +'\n')

            print_success(f"TXT report saved to {filename}")
    except (OSError, TypeError) as error:
        print_error(f"Failed to export TXT report: {error}")


            
# JSON Export function
def export_json(filename,ip,mode,results,duration):
    report = {
        "tool": "PortVex",
        "version": VERSION,
        
        "target": ip,
        "mode": mode,

        "timestamp": datetime.now().isoformat(),
        "duration": round(duration, 3),
        "total_ports": len(results),
        "results": results
    }

    try:
        with open(filename, 'w', encoding="utf-8") as file:
            json.dump(
                report,
                file,
                indent=4
            )
        print_success(f"Report exported to {filename}")
    except OSError as error:
        print_error(f"Could not export report: {error}")
    


# Scan-Target function
def scan_target(ip ,ports ,timeout, workers):

    start_time = time.time()
    results = []

    total_ports = len(ports)
    completed_ports = 0

    print_info(f"Starting scan against {ip}")
    print_info(f"Scanning {total_ports} TCP ports...")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_port, ip, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                results.append(result)
            completed_ports += 1

            show_progress(completed_ports, total_ports)
    duration = time.time() - start_time

    # Sort results by port number
    results.sort(key=lambda result: result["port"])
    print_success("Scanning completed!")

    return results, duration

def print_section(title):
    print("\n" + "*" *10)
    print(title)
    print("*" * 10)
# Print-info function(loading)
def print_info(message):
    print(f"{message}")

# Print-Success function(loading)
def print_success(message):
    print(f"{message}")

# Print-Error function(loading)
def print_error(message):
    print(f"{message}")

# Print-Warning function(loading)
def print_warning(message):
    print(f"{message}")

# Print-Banner function(loading)
def print_banner():
    print(f"{Banner}")



# #~[Main loop]~#
def main():
    args = parse_arguments()

    print_banner()

    # Get Ports
    ports = get_ports(
        args.mode,
        args.port
    )

    if not ports:
        print_error("No ports selected.")
        return
    
    # start scan
    results, duration = scan_target(
        args.ip, 
        ports,
        args.timeout,
        args.workers
    )

    # Display results
    display_summary(
        args.ip,
        args.mode,
        results,
        duration
    )

    # Export TXT
    if args.txt:
        export_txt(
            args.txt,
            args.ip,
            args.mode,
            results,
            duration
        )
    # Export JSON
    if args.json:

        export_json(
            args.json,
            args.ip,
            args.mode,
            results,
            duration
        )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user.")
"""
