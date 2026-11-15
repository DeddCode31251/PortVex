# PortVex
A command-line network reconnaissance tool written in Python.
This project aims to build a lightweight and practical network reconnaissance tool that helps users discover open TCP ports, identify common services, and analyze basic network exposure

PortVex is a student project, it's goal is to build a Cybersecurity/Penetration-testing tool

# Preview
<img width="866" height="805" alt="4" src="https://github.com/user-attachments/assets/06fd6f14-55e9-43f2-bf70-813fec1fe541" />
<img width="933" height="346" alt="1" src="https://github.com/user-attachments/assets/650c9af4-71d6-42e7-a53c-026e162f8e10" />

# Features
- Multiple Scanning Modes
- Multithreaded Scanning
- Service Identification
- Customizable Timeout
- Worker Configuration
- Colored Terminal Output
- Scan Statistics
- Report Export
- IPv4 and IPv6 Support

# Built With
- Python3
- socket
- ipaddress
- argparse
- concurrent.futures
- json

# Installation
Close the repository
```bash
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
# Usage

General syntax:
```
python3 portvex.py -i <TARGET_IP> [OPTIONS]
```
1. Scan a specific port
```
python3 portvex.py -i 127.0.0.1 -p 80 --mode current
```
2. Scan common ports
```
python3 portvex.py -i 127.0.0.1 --mode common
```
3. Scan all TCP ports
```
python3 portvex.py -i 127.0.0.1 --mode full
```
4. Customize timeout and workers
```
python3 portvex.py -i 127.0.0.1 --mode common -t 2 -w 150
```
5. Export results

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

# Author 
Deadcode

# License 
MIT
