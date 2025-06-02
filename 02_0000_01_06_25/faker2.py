from scapy.all import *
from concurrent.futures import ThreadPoolExecutor
import socket
from netaddr import IPNetwork

COMMON_PORTS = [22, 80, 135, 139, 443, 445, 3389, 554]

def syn_scan(ip, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=0)  # RST to close
        return True
    return False

def scan_ip(ip):
    for port in COMMON_PORTS:
        if syn_scan(ip, port):
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = "Unknown"
            return {"ip": ip, "port": port, "hostname": hostname}
    return None

def scan_subnet(subnet):
    ip_list = [str(ip) for ip in IPNetwork(subnet).iter_hosts()]
    results = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        for res in executor.map(scan_ip, ip_list):
            if res:
                results.append(res)
    return results

if __name__ == "__main__":
    subnet = "172.16.20.0/24"
    print(f"Scanning subnet {subnet} with common ports...\n")
    devices = scan_subnet(subnet)
    print("Detected devices (accepted TCP SYN):\n")
    for d in devices:
        print(f"- IP: {d['ip']} | Port: {d['port']} | Hostname: {d['hostname']}")
