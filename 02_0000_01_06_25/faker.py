from scapy.all import *
from concurrent.futures import ThreadPoolExecutor

def send_syn(ip, port):
    pkt = IP(dst=ip)/TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=1, verbose=0)
    if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
        # Gửi RST để đóng kết nối ngay
        send(IP(dst=ip)/TCP(dport=port, flags="R"), verbose=0)
        return ip
    return None

def scan_subnet(subnet, port):
    ip_list = [str(ip) for ip in IPNetwork(subnet).iter_hosts()]
    active_hosts = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = list(executor.map(lambda ip: send_syn(ip, port), ip_list))

    for ip in results:
        if ip:
            active_hosts.append(ip)
    return active_hosts

if __name__ == "__main__":
    subnet = "172.16.20.0/24"  # Thay bằng subnet của bạn
    port = 445  # Dùng SMB (phổ biến trên Windows)
    print(f"Scanning {subnet} on port {port}...\n")
    results = scan_subnet(subnet, port)
    print("Active devices (responding to TCP SYN):")
    for ip in results:
        print(f"- {ip}")
