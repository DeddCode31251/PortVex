# PortVex

**A lightweight command-line network reconnaissance tool written in Python.**

PortVex is a network reconnaissance tool designed to discover open TCP ports, identify services, inspect basic network exposure, and generate scan reports.

This project is developed as a student cybersecurity project, with a focus on building practical penetration-testing and network analysis tools.

> **Disclaimer:** Only scan systems you own or have explicit permission to test, such as your own lab, CTF machines, or in-scope bug bounty targets.

**Current Version:** `2.2.0`

**Playable Version:** `https://deddcode31251.github.io/PortVex/`
---

## Preview

<img width="868" height="725" alt="PortVex terminal preview" src="https://github.com/user-attachments/assets/f10e3de6-401f-4068-8560-4238cb7fac0b" />

<img width="761" height="818" alt="PortVex scan preview" src="https://github.com/user-attachments/assets/77183088-8899-4c38-883d-f5f29a81ba84" />

<img width="866" height="805" alt="PortVex output preview" src="https://github.com/user-attachments/assets/06fd6f14-55e9-43f2-bf70-813fec1fe541" />

<img width="933" height="346" alt="PortVex report preview" src="https://github.com/user-attachments/assets/650c9af4-71d6-42e7-a53c-026e162f8e10" />

---

## Features

### Scanning

- Three scan modes: current ports, common ports, and all 65,535 TCP ports.
- Custom port lists and ranges, such as `22,80,8000-8100`.
- Asynchronous scanning using Python's `asyncio`.
- Configurable concurrent connections.
- Configurable connection timeouts and retries.
- Optional connection rate limiting.
- IPv4, IPv6, and hostname support.
- Live display of discovered open ports.
- Distinguishes between open, closed, and filtered ports.
- Handles interrupted scans with `Ctrl+C` while preserving discovered results.

### Service Detection

- Service identification using actual service banners.
- TLS detection, including on non-standard ports.
- Displays detected TLS versions.
- Optional banner grabbing for faster scans.

### Scan Profiles

- Predefined scan profiles for convenient configuration.
- Profile-based settings for scan parameters such as workers, timeouts, and retries.

### Output and Reporting

- Colored terminal output.
- Quiet mode for command-line pipelines.
- Scan statistics and summaries.
- TXT report export.
- JSON report export.
- HTML report export.

---

## Built With

PortVex uses Python's standard library.

| Technology | Purpose |
|---|---|
| Python 3 | Main programming language |
| asyncio | Asynchronous scanning |
| socket | Network connections |
| ssl | TLS detection |
| argparse | Command-line argument parsing |
| re | Regular expressions |
| json | JSON report generation |
| dataclasses | Structured data management |

No third-party packages are required to run PortVex from source.

---

## Installation

### Option 1: Download a Release

PortVex releases include a ready-to-run Linux binary built with PyInstaller.

1. Visit the [PortVex Releases](https://github.com/DeddCode31251/PortVex/releases) page.
2. Select the version you want.
3. Find the **Assets** section.
4. Download the `portvex` binary.

Make it executable:

```bash
chmod +x portvex
```

Run it:

```bash
./portvex --help
```

You can also download the latest release directly:

```bash
curl -L -o portvex https://github.com/DeddCode31251/PortVex/releases/latest/download/portvex

chmod +x portvex

./portvex --help
```

To run PortVex from anywhere, move it into your PATH:

```bash
sudo mv portvex /usr/local/bin/
```

Example:

```bash
portvex -i 127.0.0.1 --mode common
```

**Platform compatibility:** The provided binary is built for 64-bit Linux. PyInstaller executables are platform-specific. Windows and macOS users should use Option 2.

If you encounter a GLIBC compatibility error, running from source may be a better option.

### Option 2: Run From Source

Requirements:

- Python 3.10 or newer.
- Git.

Clone the repository:

```bash
git clone https://github.com/DeddCode31251/PortVex.git
```

Navigate into the project:

```bash
cd PortVex
```

Run PortVex:

```bash
python3 portvex.py --help
```

No additional packages are required.

---

## Usage

General syntax:

```bash
python3 portvex.py -i <TARGET> [OPTIONS]
```

If you downloaded the binary, replace `python3 portvex.py` with `./portvex`.

### Command-Line Options

| Option | Description |
|---|---|
| `-i`, `--ip` | Target IPv4, IPv6, or hostname (required) |
| `-p`, `--port` | Ports to scan: `80`, `22,80,443`, `1-1024`, or `-` for all |
| `--mode` | Scan mode: `current`, `common`, or `full` |
| `--profile` | Apply a predefined scan configuration |
| `-t`, `--timeout` | Connection timeout in seconds |
| `-w`, `--workers` | Maximum concurrent connections |
| `-r`, `--retries` | Number of retries for timed-out ports |
| `--rate` | Maximum new connections per second; `0` means unlimited |
| `--no-banner` | Skip banner grabbing and service detection |
| `-q`, `--quiet` | Print only `host:port` for each open port; implies `--no-banner` |
| `--txt FILE` | Export results as a text report |
| `--json FILE` | Export results as a JSON report |
| `--html FILE` | Export results as an HTML report |
| `--version` | Display the current version |

For exact default values and available profiles, use:

```bash
python3 portvex.py --help
```

If you specify `-p` without `--mode`, PortVex scans only the selected ports.

If you combine `-p` with `--mode common` or `--mode full`, the custom port selection is ignored and a warning is displayed.

---

## Examples

### 1. Scan a Specific Port

```bash
python3 portvex.py -i 127.0.0.1 -p 80 --mode current
```

### 2. Scan Multiple Ports and Ranges

```bash
python3 portvex.py -i 127.0.0.1 -p 22,80,443,8000-8100
```

### 3. Scan Common Ports

```bash
python3 portvex.py -i 127.0.0.1 --mode common
```

### 4. Scan All TCP Ports

```bash
python3 portvex.py -i 127.0.0.1 --mode full
```

### 5. Customize Timeout and Workers

```bash
python3 portvex.py -i 127.0.0.1 --mode common -t 2 -w 150
```

### 6. Apply a Scan Profile

```bash
python3 portvex.py -i 127.0.0.1 --profile fast
```

### 7. Limit Connection Rate

For example, limit new connections to 50 per second:

```bash
python3 portvex.py -i 127.0.0.1 --mode full --rate 50
```

### 8. Skip Banner Grabbing

```bash
python3 portvex.py -i 127.0.0.1 --mode common --no-banner
```

### 9. Quiet Mode

Useful when passing results to other command-line tools:

```bash
python3 portvex.py -i 127.0.0.1 --mode full -q
```

### 10. Export a TXT Report

```bash
python3 portvex.py -i 127.0.0.1 --mode common --txt report.txt
```

### 11. Export a JSON Report

```bash
python3 portvex.py -i 127.0.0.1 --mode common --json report.json
```

### 12. Generate an HTML Report

```bash
python3 portvex.py -i 127.0.0.1 --mode common --html report.html
```

### 13. Export Multiple Report Formats

```bash
python3 portvex.py -i 127.0.0.1 --mode common \
    --txt report.txt \
    --json report.json \
    --html report.html
```

### 14. Use PortVex With Nmap

PortVex can perform an initial scan, and the discovered open ports can be passed to Nmap for further service and version detection.

```bash
ports=$(python3 portvex.py -i 127.0.0.1 --mode full -w 1000 -t 0.5 -q | cut -d: -f2 | paste -sd,)

nmap -sCV -p"$ports" 127.0.0.1
```

Only run this against systems you are authorized to test.

---

## Understanding the Output

Example:

```text
PORT      STATE   SERVICE         INFO
2222/tcp  open    ssh             OpenSSH_8.2p1
6379/tcp  open    redis           -NOAUTH Authentication required.
8080/tcp  open    http            HTTP/1.0 200 OK | Apache/2.4.41 (Ubuntu)
8443/tcp  open    https           [TLSv1.3] HTTP/1.0 200 OK | Apache/2.4.41 (Ubuntu)
9999/tcp  open    unknown
```

### Port States

| State | Meaning |
|---|---|
| `open` | The connection was successfully established. |
| `closed` | The host responded but refused the connection. |
| `filtered` | No response was received, often because a firewall dropped the packets. |

### Service Identification

A service name ending with `?`, such as `ssh?`, indicates a guess based on the port number.

A service name without `?` indicates that PortVex identified the service from its response.

When many ports appear as filtered, a firewall or network filtering may be preventing PortVex from receiving responses.

### Terminal Colors

| Color | Meaning |
|---|---|
| Red | Services that may require additional security attention, such as Telnet, FTP, SMB, RDP, Redis, MongoDB, and Docker. |
| Green | Open ports and services such as SSH and HTTPS. |
| Yellow | Web services. |
| Magenta | Unknown services and TLS information. |
| Orange | Filtered ports. |

Terminal colors are automatically disabled when output is piped or when `NO_COLOR` is set.

---

## Building Your Own Binary

You can build a standalone executable using PyInstaller.

Install PyInstaller:

```bash
pip install pyinstaller
```

Build PortVex:

```bash
pyinstaller --onefile portvex.py
```

The executable will be generated inside:

```text
dist/
```

Build the executable on the same operating system and architecture you intend to run it on.

---

## Contributing

Contributions are welcome!

If you want to improve PortVex, fix bugs, suggest features, or improve documentation, please read:

[CONTRIBUTING.md](CONTRIBUTING.md)

Before submitting changes, make sure they are tested and follow the project's development guidelines.

---

## Security

If you discover a security vulnerability, please follow the instructions in:

[SECURITY.md](SECURITY.md)

Do not publicly disclose vulnerabilities before they have been responsibly reviewed.

---

## Author

**Deadcode**

---

## License

PortVex is distributed under the MIT License.

See [LICENSE](LICENSE) for details.
