import json
import time
import urllib.request

TARGET = "http://localhost:8081"
SIMULATED_SOURCE_IP = "45.83.1.10"
PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8081]

for port in PORTS:
    request = urllib.request.Request(
        f"{TARGET}/api/probes/{port}",
        headers={
            "User-Agent": "nmap/portfolio-lab",
            "X-Forwarded-For": SIMULATED_SOURCE_IP
        }
    )

    with urllib.request.urlopen(request, timeout=5) as response:
        payload = json.loads(response.read().decode("utf-8"))
        print(json.dumps(payload, indent=2))

        if payload.get("status") == "incident_created":
            print("Incident triggered.")
            break

    time.sleep(0.4)
