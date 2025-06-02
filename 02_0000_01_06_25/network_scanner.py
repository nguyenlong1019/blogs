import ipaddress
import scapy.all as scapy
import socket

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

def scan(ip_range):
    # Tạo gói ARP yêu cầu cho tất cả IP trong mạng
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request
    answered = scapy.srp(packet, timeout=2, verbose=0)[0]

    devices = []
    for sent, received in answered:
        ip = received.psrc
        hostname = get_device_name(ip)
        devices.append({"ip": ip, "hostname": hostname})
    
    return devices

if __name__ == "__main__":
    # subnet = "192.168.1.0/24"
    subnet = "172.16.20.0/24"
    print(f"Scanning subnet: {subnet}...\n")

    results = scan(subnet)
    print("Found devices:")
    for device in results:
        print(f"- IP: {device['ip']} | Hostname: {device['hostname']}")
