import socket 
import requests 
import ssl 
from urllib.parse import urlparse 
from jinja2 import Template 
import os 


SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy"
]


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 3306: "MySQL", 8080: "HTTP-Alt"
}


def check_http_headers(url):
    result = {"status_code": None, "server": None, "headers": {}}
    try:
        response = requests.get(url, timeout=10)
        result["status_code"] = response.status_code
        result["server"] = response.headers.get("Server", "N/A")
        for header in SECURITY_HEADERS:
            result["headers"][header] = response.headers.get(header, None)
    except Exception as e:
        result["error"] = str(e)
    return result


def check_ssl_certificate(hostname):
    cert_info = dict()
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                cert_info["issuer"] = cert.get("issuer")
                cert_info["subject"] = cert.get("subject")
                cert_info["notBefore"] = cert.get("notBefore")
                cert_info["notAfter"] = cert.get("notAfter")
    except Exception as e:
        cert_info["error"] = str(e)
    return cert_info


def scan_ports(hostname):
    open_ports = []
    for port, service in COMMON_PORTS.items():
        try:
            with socket.create_connection((hostname, port), timeout=1):
                open_ports.append((port, service))
        except Exception as e:
            pass 
    return open_ports


def test_sqli_xss(url):
    payloads = {
        "SQLi": "' OR '1'='1",
        "XSS": "<script>alert('XSS')</script>"
    }

    results = dict()
    for test, payload in payloads.items():
        try:
            response = requests.get(url, params={'test': payload}, timeout=10)
            if payload in response.text:
                results[test] = "Possible vulnerability detected!"
            else:
                results[test] = "No vulnerability detected"
        except Exception as e:
            results[test] = f"Error: {e}"
    return results 


def generate_html_report(data, filename="scan_report.html"):
    template = Template("""
    <html>
    <head><title>Security Scan Report</title></head>
    <body style="font-family:sans-serif">
    <h1>Security Scan Report for {{ target }}</h1>
    <h2>HTTP Info</h2>
    <p>Status Code: {{ http.status_code }}</p>
    <p>Server: {{ http.server }}</p>
    <h3>Security Headers</h3>
    <ul>
    {% for k, v in http.headers.items() %}
        <li>{{ k }}: {{ "Present" if v else "Missing" }}</li>
    {% endfor %}
    </ul>
    <h2>SSL Certificate</h2>
    <ul>
    {% for k, v in ssl.items() %}
        <li>{{ k }}: {{ v }}</li>
    {% endfor %}
    </ul>
    <h2>Open Ports</h2>
    <ul>
    {% for port, service in ports %}
        <li>{{ port }} ({{ service }})</li>
    {% endfor %}
    </ul>
    <h2>Vulnerability Test</h2>
    <ul>
    {% for k, v in vuln.items() %}
        <li>{{ k }}: {{ v }}</li>
    {% endfor %}
    </ul>
    </body>
    </html>
    """)
    output = template.render(**data)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(output)
    return filename


def run_full_scan(target_url):
    parsed = urlparse(target_url)
    hostname = parsed.hostname or target_url.replace("http://", "").replace("https://", "")
    print(f"[+] Scanning: {target_url}")

    http_info = check_http_headers(target_url)
    ssl_info = check_ssl_certificate(hostname)
    open_ports = scan_ports(hostname)
    vuln_test = test_sqli_xss(target_url)

    report_data = {
        "target": target_url,
        "http": http_info,
        "ssl": ssl_info,
        "ports": open_ports,
        "vuln": vuln_test
    }

    report_file = generate_html_report(report_data)
    print(f"\n✅ Report generated: {report_file}")
    return report_file


if __name__ == "__main__":
    url = input("Enter website URL (e.g., https://example.com): ")
    run_full_scan(url)
