import socket
import requests
from scapy.all import *
from impacket.smbconnection import SMBConnection

def get_os_from_ttl(ip):
    try:
        pkt = IP(dst=ip)/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        if resp:
            ttl = resp.ttl
            if ttl >= 120:
                return f"Windows (TTL={ttl})"
            elif ttl >= 60:
                return f"Linux/Unix (TTL={ttl})"
            elif ttl >= 250:
                return f"Router/IoT (TTL={ttl})"
            else:
                return f"Unknown OS (TTL={ttl})"
        else:
            return "No response"
    except Exception as e:
        return f"Error: {e}"

def grab_banner(ip, port):
    try:
        with socket.socket() as s:
            s.settimeout(2)
            s.connect((ip, port))
            banner = s.recv(1024).decode(errors='ignore').strip()
            return banner if banner else "Empty response"
    except Exception as e:
        return f"Timeout/Error: {e}"

def http_fingerprint(ip):
    try:
        resp = requests.get(f"http://{ip}", timeout=2)
        title = ""
        if "<title>" in resp.text:
            title = resp.text.split("<title>")[1].split("</title>")[0]
        return {
            "status_code": resp.status_code,
            "server": resp.headers.get("Server", "Unknown"),
            "title": title
        }
    except Exception as e:
        return {"error": str(e)}

def get_smb_info(ip):
    try:
        conn = SMBConnection(ip, ip, timeout=2)
        conn.login('', '')  # Anonymous
        return conn.getServerOS()
    except Exception as e:
        return f"SMB error: {e}"

def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unknown"

def scan_target(ip):
    print(f"=== Scanning target: {ip} ===\n")

    print("[*] Hostname:", get_hostname(ip))
    print("[*] OS Guess via TTL:", get_os_from_ttl(ip))
    
    print("\n[*] Banner Grabbing:")
    for port in [22, 445, 80]:
        banner = grab_banner(ip, port)
        print(f"  - Port {port}: {banner}")

    print("\n[*] HTTP Fingerprint:")
    http_info = http_fingerprint(ip)
    for key, value in http_info.items():
        print(f"  {key}: {value}")

    print("\n[*] SMB OS Info (port 445):")
    print(get_smb_info(ip))

if __name__ == "__main__":
    target_ip = input("Enter target IP: ").strip()
    scan_target(target_ip)
