import nmap
import json

def scan_network(network_range):
    scanner = nmap.PortScanner()

    print(f"[+] Scanning: {network_range}")
    scanner.scan(hosts=network_range, arguments='-O -T4')

    results = []

    for host in scanner.all_hosts():
        host_info = {
            "ip": host,
            "hostname": scanner[host].hostname(),
            "state": scanner[host].state(),
            "os": [],
            "ports": []
        }

        # OS detection
        if 'osmatch' in scanner[host]:
            for os in scanner[host]['osmatch']:
                host_info["os"].append({
                    "name": os["name"],
                    "accuracy": os["accuracy"]
                })

        # Port info
        if 'tcp' in scanner[host]:
            for port in scanner[host]['tcp']:
                port_data = scanner[host]['tcp'][port]
                host_info["ports"].append({
                    "port": port,
                    "state": port_data["state"],
                    "name": port_data.get("name"),
                    "product": port_data.get("product"),
                    "version": port_data.get("version")
                })

        results.append(host_info)

    return results


if __name__ == "__main__":
    network = "172.16.20.0/24"  # Đổi thành mạng LAN của bạn
    output_file = "nmap_results.json"

    scan_data = scan_network(network)

    with open(output_file, "w") as f:
        json.dump(scan_data, f, indent=4)

    print(f"[+] Scan completed. Results saved to: {output_file}")
