# PortVex
A command-line network reconnaissance tool written in Python.
This project aims to build a lightweight and practical network reconnaissance tool that helps users discover open TCP ports, identify common services, and analyze basic network exposure

PortVex is a student project, its goal is to build a Cybersecurity/Penetration-testing tool

Only scan systems you own or have clear permission to test (your own lab, CTF machines, in-scope bug bounty targets).

Current version: **2.0.0**

# Preview
<img width="868" height="725" alt="Screenshot From 2026-11-19 22-11-50" src="https://github.com/user-attachments/assets/f10e3de6-401f-4068-8560-4238cb7fac0b" />

<img width="761" height="818" alt="Screenshot From 2026-11-16 20-09-29" src="https://github.com/user-attachments/assets/77183088-8899-4c38-883d-f5f29a81ba84" />

<img width="866" height="805" alt="4" src="https://github.com/user-attachments/assets/06fd6f14-55e9-43f2-bf70-813fec1fe541" />

<img width="933" height="346" alt="1" src="https://github.com/user-attachments/assets/650c9af4-71d6-42e7-a53c-026e162f8e10" />

# Features
- Three scan modes: one port, the common ports list, or all 65535 ports
- Port lists and ranges, like `22,80,8000-8100`
- Asynchronous scanning (asyncio), so hundreds of connections run at the same time
- Tells apart open, closed and filtered ports
- Service identification from the real banner, not only from the port number
- TLS detection, even on non-standard ports, and it shows the TLS version
- Retries for ports that time out, plus an optional rate limit
- Open ports are printed live while the scan is still running
- Quiet mode that prints only `host:port`, useful for piping into other tools
- Ctrl+C stops the scan but still shows what was found so far
- Colored output (turns off by itself when piped or when `NO_COLOR` is set)
- Scan statistics
- TXT and JSON report export
- IPv4, IPv6 and hostnames

# Built With
- Python 3
- asyncio
- socket
- ssl
- argparse
- re
- json
- dataclasses

# Installation

## Option 1: Download the release (no Python needed)

Every release has a ready-to-run binary made with PyInstaller.

1. Open the [Releases page](https://github.com/DeddCode31251/PortVex/releases)
2. Pick the version you want (the latest one is at the top)
3. Scroll down to **Assets** and download the `portvex` file
4. Open a terminal in the folder where it was saved and make it executable:

```
chmod +x portvex
```

5. Run it:

```
./portvex --help
```

You can also download it straight from the terminal:

```
curl -L -o portvex https://github.com/DeddCode31251/PortVex/releases/latest/download/portvex
chmod +x portvex
./portvex --help
```

If you want to run it from anywhere, move it into your PATH:

```
sudo mv portvex /usr/local/bin/
portvex -i 127.0.0.1 --mode common
```

The binary is built for Linux (64-bit). PyInstaller builds only work on the system they were made on, so on Windows or macOS use Option 2 below. If you get a `GLIBC` error on an older distro, use Option 2 as well.

## Option 2: Run from source

You need Python 3.10 or newer.

Clone the repository
```
git clone https://github.com/DeddCode31251/PortVex.git
```

Navigate into the project directory
```
cd PortVex
```

Run PortVex
```
python3 portvex.py --help
```

There are no extra packages to install, it only uses the standard library.

# Usage

General syntax:
```
python3 portvex.py -i <TARGET> [OPTIONS]
```
If you downloaded the binary, replace `python3 portvex.py` with `./portvex`.

## Options

| Option | What it does |
|---|---|
| `-i`, `--ip` | Target IPv4, IPv6 or hostname (required) |
| `-p`, `--port` | Ports to scan: `80`, `22,80,443`, `1-1024`, `22,8000-8100`, or `-` for all |
| `--mode` | `current` (only the ports from `-p`), `common` or `full` |
| `-t`, `--timeout` | Connection timeout in seconds (default 1.5) |
| `-w`, `--workers` | Max connections at the same time (default 500) |
| `-r`, `--retries` | Retries for ports that time out (default 1) |
| `--rate` | Max new connections per second, 0 means no limit |
| `--no-banner` | Skip banner grabbing and service detection, faster |
| `-q`, `--quiet` | Print only `host:port` for each open port, implies `--no-banner` |
| `--txt FILE` | Save the report as text |
| `--json FILE` | Save the report as JSON |
| `--version` | Show the version |

If you give `-p` without `--mode`, only those ports are scanned. If you give `--mode common` or `--mode full` together with `-p`, the `-p` part is ignored and you get a warning.

## Examples

1. Scan a specific port
```
python3 portvex.py -i 127.0.0.1 -p 80 --mode current
```
2. Scan a list and a range of ports
```
python3 portvex.py -i 127.0.0.1 -p 22,80,443,8000-8100
```
3. Scan common ports
```
python3 portvex.py -i 127.0.0.1 --mode common
```
4. Scan all TCP ports
```
python3 portvex.py -i 127.0.0.1 --mode full
```
5. Customize timeout and workers
```
python3 portvex.py -i 127.0.0.1 --mode common -t 2 -w 150
```
6. Go easy on the target (50 new connections per second)
```
python3 portvex.py -i 127.0.0.1 --mode full --rate 50
```
7. Use PortVex for a fast first pass, then give the open ports to nmap
```
ports=$(python3 portvex.py -i 127.0.0.1 --mode full -w 1000 -t 0.5 -q | cut -d: -f2 | paste -sd,)
nmap -sCV -p$ports 127.0.0.1
```
8. Export results

Export as TXT:
```
python3 portvex.py -i 127.0.0.1 --mode common --txt report.txt
```
Export as JSON:
```
python3 portvex.py -i 127.0.0.1 --mode common --json report.json
```
Export both formats:
```
python3 portvex.py -i 127.0.0.1 --mode common --txt report.txt --json report.json
```

## Reading the output

```
PORT      STATE   SERVICE         INFO
2222/tcp  open    ssh             OpenSSH_8.2p1
6379/tcp  open    redis           -NOAUTH Authentication required.
8080/tcp  open    http            HTTP/1.0 200 OK | Apache/2.4.41 (Ubuntu)
8443/tcp  open    https           [TLSv1.3] HTTP/1.0 200 OK | Apache/2.4.41 (Ubuntu)
9999/tcp  open    unknown
```

Port states:
- open: the connection worked
- closed: the host answered and refused the connection
- filtered: nothing came back, usually a firewall dropping the packets

A service name with a `?` at the end (like `ssh?`) is only a guess based on the port number. Without the `?`, the service answered and PortVex recognised it. When most ports show as filtered, PortVex tells you a firewall is probably in the way.

Colors in the terminal:
- red: services that are often attacked or misconfigured (telnet, ftp, smb, rdp, redis, mongodb, docker...)
- green: open state, and encrypted or standard services like ssh and https
- yellow: web services
- magenta: unknown services and TLS versions
- orange: filtered ports

# Build your own binary

If you want to make the single-file version yourself:

```
pip install pyinstaller
pyinstaller --onefile portvex.py
```

The finished file ends up in the `dist/` folder. Build it on the same type of system you plan to run it on.

# Author
Deadcode

# License
MIT
