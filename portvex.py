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

# #~[Important Functions]~#

# Loading function
def loading_UI(timer):
    print("Loading.")
    time.sleep(timer)
    print("Loading..")
    time.sleep(timer)
    print("Loading...")
    time.sleep(0.5)



# #~[Args]~#
parser = argparse.ArgumentParser(description="PortVex")


# Ip search
parser.add_argument("-i", required=True, help="IP to scan")
parser.add_argument('-p', required=True, type=int, help="Single TCP port to check")
parser.add_argument(
    "--mode",
    choices=('common','full'),
    default='common',
    help="Select common checks or a full port range",
)

args = parser.parse_args()

# Validate inputes
try:
    ipaddress.ip_address(args.i)
except ValueError:
    parser.error("[!!]: Enter a valid IP address")

if not 1 <= args.p <= 65535:
    parser.error("[!!]: Port must be between 1 and 65535")





# #~[Welcome]~#
print("PORTVEX has Started!")
print(r"""

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
""")
time.sleep(1)
print("Type -h or -help for guide")
print("CLN Started")
loading_UI(0.5)

# #~[Functions]~#

# Scan-Target-Ip function
def scan_target_ip(ip ,port ,mode):
    print(f"Checking {ip}:{port} ({mode} mode)")
    
    try:
        with socket.create_connection((ip,port), timeout=3):
            print(f"TCP port {port} is reachable")
    except:
        print(f"TCP port {port} is not reachable")
    
    

scan_target_ip(args.i ,args.p ,args.mode)

