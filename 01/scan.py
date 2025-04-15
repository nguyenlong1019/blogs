import requests 
import ssl 
import socket 
from urllib.parse import urlparse 


SECURITY_HEADERS = [
    'Content-Security-Policy', # XSS
    'Strict-Transport-Security', # HTTPS
    'X-Content-Type-Options', # MIME-sniffing
    'X-Frame-Options', # clickjacking (iframe)
    'X-XSS-Protection', # XSS filter
    'Referer-Policy', # Referer control
    'Permissions-Policy' # Limit API: camera, mic, geolocation
]


def check_http_headers(url):
    try:
        response = requests.get(url, timeout=10)
        print(f"\n[+] HTTP Status Code: {response.status_code}")
        print(f"[+] Server Header: {response.headers.get('Server', 'N/A')}")

        print("\n[+] Checking Security Headers:")
        for header in SECURITY_HEADERS:
            if header in response.headers:
                print(f"  [✔] {header}: {response.headers[header]}")
            else:
                print(f"  [✘] {header}: Missing")
    except Exception as e:
        print(f"[!] Error checking headers: {e}")

    
def check_ssl_certificate(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(cert)
                print(f"\n[+] SSL Certificate Info:")
                print(f"  - Issuer: {cert['issuer']}") # tổ chức cấp chứng chỉ
                print(f"  - Subject: {cert['subject']}") # tên miền được cấp
                print(f"  - Valid From: {cert['notBefore']}") 
                print(f"  - Valid To: {cert['notAfter']}")
    except Exception as e:
        print(f"[!] Error checking SSL cert: {e}")



def run_scanner(target_url):
    print(f"\n==== Security Scanner Started ====\nTarget: {target_url}")
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url.replace("http://", "").replace("https://", "")
    check_http_headers(target_url)
    check_ssl_certificate(hostname)
    print("\n==== Scan Completed ====\n")


if __name__ == '__main__':
    website = input("Enter website URL (e.g., https://example.com): ")
    run_scanner(website)

# pip install requests