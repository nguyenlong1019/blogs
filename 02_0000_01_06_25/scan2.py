import subprocess
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def ping_and_get_name(ip):
    try:
        subprocess.run(['ping', '-c', '1', '-W', '1', str(ip)], stdout=subprocess.DEVNULL)
        name = socket.gethostbyaddr(str(ip))[0]
    except:
        name = "Unknown"
    return (str(ip), name)

if __name__ == "__main__":
    subnet = ipaddress.IPv4Network("172.16.20.0/24", strict=False)
    print("Scanning using ping...\n")

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_and_get_name, subnet.hosts()))

    for ip, name in results:
        print(f"- IP: {ip} | Hostname: {name}")
