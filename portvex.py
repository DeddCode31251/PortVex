# PortVex 
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


from dataclasses import asdict, dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

__version__ = "2.0.0"

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
    50000: 'jenkis-agent',
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
HTTP_PROBE = b"HEAD / HTTP/1.0\r\nHOST: %s\r\nUser-Agent:PortVex\r\n\r\n"
GENERIC_PROBE = b"\r\n"

# #~[Output Helpers]~#

class C:
    on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    RED,GREEN,YELLOW,BLUE,CYAN,DIM,BOLD,END = (
        ('\033[91m', '\033[92m', '\033[93m', '\033[94m',
        '\033[96m', '\033[2m', '\033[1m', '\033[0m') if on else ("",) * 8
    )

# Banner

Banner = rf"""{C.CYAN}

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
 ___           _   __     __ 
| _ \___ _ _ _| |_ \ \   / /____ __
|  _/ _ \ '_|_  _|  \ \ / / -_) \ /
|_| \___/_|   |_|    \_/ \___/_\_\  v{__version__}
 {C.END}{C.DIM} async TCP recon - use only on authorised
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
    state: str # open | closed | filtered
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
    for part in spec.split('.'):
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
        epilog(
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
    p.add_argument('--no-banner', aaction="store_true", 
    help="skip banner grabbing/service detection (faster)")
    p.add_argument('-q', '--quiet', action='store_true',
    help="print only 'host:port' per open port (pipe-friendly, implies --no-banner)")
    p.add_argument('--txt', metavar="FILE", 
    help="export report as text")
    p.add_argument('--json',metavar="FILE", help="export report as JSON")
    p.add_argument('--version', action="version", version=f"PortVex {__version__}")
    
    return p

class RateLimiter:
    pass

async def _close(writer: asyncio.Stream.Writer) -> None:
    pass

async def probe_port(host: str, port: int, timeout: float, retries: int, limiter: RateLimiter) -> PortResult:
    pass

async def _talk(host: str, sni: str | None, port: int, use_tls: bool, passive: bool, probe:bytes | None, timeout: float):
    pass

def _clean(data: bytes) -> str:
    pass

def identify(port: int, data:bytes, tls:str) -> tuple[str,str]:
    pass

async def fingerprint(host: str, sni:str | None, port:int, timeout: float) -> tuple[str, str, str]:
    async def attempt(user_tls: bool):
        pass

async def run_scan(host: str, ports: list[int], args, state: ScanState) -> None:
    async def worker():
        pass

    async def progress():
        pass

def _is_ip(value:str) -> bool:
    pass

async def resolve(target: str) -> str:
    pass

def fd_limit_cap(requested: int) -> int:
    pass

def render_table(state: ScanState) -> list[str]:
    pass

def write_reports(args, ip: str, state: ScanState, started:datetime, duration: float) -> None:
    pass

def selected_ports(args, parser) -> list[int]:
    pass

async def amain(args, ports: list[int], state: ScanState) -> str:
    pass

def main() -> int:
    pass

if __name__ == "__main__":
    sys.exit(main())
    
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
