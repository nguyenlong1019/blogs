import requests

# 1. XSS
def test_xss_attack(url):
    print("[*] Testing XSS...")
    payload = "<script>alert('XSS')</script>"
    data = {"input": payload}
    try:
        res = requests.post(url, data=data)
        if payload in res.text:
            print("[!] XSS vulnerability detected!")
        else:
            print("[+] XSS test passed.")
    except Exception as e:
        print(f"[X] XSS test failed: {e}")

# 2. CSRF
def test_csrf_attack(url):
    print("[*] Testing CSRF...")
    data = {"username": "admin", "password": "123"}
    try:
        res = requests.post(url, data=data)
        if res.status_code == 403:
            print("[+] CSRF protection is working.")
        else:
            print("[!] Potential CSRF vulnerability!")
    except Exception as e:
        print(f"[X] CSRF test failed: {e}")

# 3. SQL Injection
def test_sql_injection(url):
    print("[*] Testing SQL Injection...")
    payload = "' OR '1'='1"
    data = {"username": payload, "password": "irrelevant"}
    try:
        res = requests.post(url, data=data)
        if "Welcome" in res.text or res.status_code == 200:
            print("[!] SQL Injection vulnerability detected!")
        else:
            print("[+] SQL Injection test passed.")
    except Exception as e:
        print(f"[X] SQL Injection test failed: {e}")

# 4. Clickjacking
def test_clickjacking(url):
    print("[*] Testing Clickjacking...")
    try:
        res = requests.get(url)
        if "X-Frame-Options" not in res.headers:
            print("[!] X-Frame-Options header missing - possible clickjacking!")
        else:
            print(f"[+] X-Frame-Options: {res.headers['X-Frame-Options']}")
    except Exception as e:
        print(f"[X] Clickjacking test failed: {e}")

# 5. Host Header Injection
def test_host_header_injection(url):
    print("[*] Testing Host Header Injection...")
    headers = {"Host": "evil.com"}
    try:
        res = requests.get(url, headers=headers)
        if "evil.com" in res.text:
            print("[!] Host header injection vulnerability!")
        else:
            print("[+] Host header validated.")
    except Exception as e:
        print(f"[X] Host header test failed: {e}")

# 6. Session Hijacking
def test_session_hijacking(url, fake_sessionid):
    print("[*] Testing Session Hijacking...")
    cookies = {"sessionid": fake_sessionid}
    try:
        res = requests.get(url, cookies=cookies)
        if "Welcome" in res.text or res.status_code == 200:
            print("[!] Session hijack may be possible!")
        else:
            print("[+] Session protection OK.")
    except Exception as e:
        print(f"[X] Session hijack test failed: {e}")

# 7. File Upload
def test_file_upload(url):
    print("[*] Testing File Upload...")
    files = {"file": ("test.php", "<?php echo 'Hacked'; ?>", "application/x-php")}
    try:
        res = requests.post(url, files=files)
        if res.status_code == 200:
            print("[!] Dangerous file uploaded! Check if it can be executed!")
        else:
            print("[+] File upload restrictions are working.")
    except Exception as e:
        print(f"[X] File upload test failed: {e}")

# Run all tests
def run_all_tests():
    base_url = "https://lightproweb.com"
    run_config = {
        "xss": f"{base_url}/search",
        "csrf": f"{base_url}/login",
        "sql": f"{base_url}/login",
        "clickjacking": f"{base_url}/",
        "host_header": f"{base_url}/",
        "session_hijack": f"{base_url}/dashboard",
        "upload": f"{base_url}/upload"
    }

    test_xss_attack(run_config["xss"])
    test_csrf_attack(run_config["csrf"])
    test_sql_injection(run_config["sql"])
    test_clickjacking(run_config["clickjacking"])
    test_host_header_injection(run_config["host_header"])
    test_session_hijacking(run_config["session_hijack"], "fake-sessionid-123")
    test_file_upload(run_config["upload"])

if __name__ == "__main__":
    run_all_tests()
