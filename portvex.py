# PortVex 
"""
PortVex is a command-line network reconnaissance tool written in Python.
Made by: Deadcode
Github: https://github.com/DeddCode31251/PortVex
"""

# #~[Libraries]~#
import argparse
import time
import ipaddress
import socket
import json

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

VERSION = "1.0.0"

# #~Terminal Colors~#
class Colors:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    PURPLE = "\033[95m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"
# #~[Important Functions]~#

# Loading function
def loading_UI(timer):
    print("Loading.")
    time.sleep(timer)
    print("Loading..")
    time.sleep(timer)
    print("Loading...")
    time.sleep(0.5)


# #~[Welcome]~#
#print("PORTVEX has Started!")

# Banner
Banner = rf"""

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

                            PORTVEX
                        Network Reconnaissance Tool
                        {VERSION}
"""
"""print()
time.sleep(1)
print("Type -h or -help for guide")
print("CLN Started")
loading_UI(0.5)"""

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
        help="Export results to a JSON file"
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

# Common Ports List
COMMON_PORTS = [
    
    # File Transffer
    20,21,

    # Remote Access
    22,23,
    3389,5900,

    # Mail Services
    25,110,143,465,587,993,995,

    # Web Services
    80,443,8080,8000,8443,8888,

    # DNS & Network Services
    53, #67,68,69,123,161,162,
    
    # Database Services
    1433,1521,3306,5432,27017,6379,

    # File Sharing
    139,445,

    # Directory Services
    389,636,

    # Application Services
    3000,5000,5001,9000,

    # Monitoring & Management
    9090, 9100,

    # Other common Services
    111,135,1723,2049, 5901,
]

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

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(scan_port, ip, port, timeout)
            for port in ports
        ]

        for future in as_completed(futures):
            result = future.result()

            if result is not None:
                results.append(result)
    duration = time.time() - start_time

    # Sort results by port number
    results.sort(key=lambda result: result["port"])

    return results, duration

def print_section(title):
    print("\n" + "*" *10)
    print(title)
    print("*" * 10)
# Print-info function(loading)
def print_info(message):
    print(f"\033[94m[*]\033[0m {message}")

# Print-Success function(loading)
def print_success(message):
    print(f"\033[92m[+]\033[0m {message}")

# Print-Error function(loading)
def print_error(message):
    print(f"\033[91m[-]\033[0m {message}")

# Print-Warning function(loading)
def print_warning(message):
    print(f"\033[91m[-]\033[0m {message}")

# Print-Banner function(loading)
def print_banner():
    print(f"{Colors.RED}{Colors.BOLD}{Banner}{Colors.RESET}")


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
