import socket
import argparse
import json
from datetime import datetime
import requests
from jinja2 import Template
import logging

def classify_risk(port, service, banner):
    """
    Very simple risk classification based on exposure context.
    This is NOT vulnerability scanning.
    """

    # Remote access services
    if port in (22, 3389):
        return "MEDIUM"

    # HTTP without useful headers
    if service == "http" and (not banner or banner.lower() == "unknown"):
        return "LOW"

    # Unknown service but banner exists → interesting
    if service == "unknown" and banner:
        return "INVESTIGATE"

    return "INFO"

# --------------------------
# Logging config
# --------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

# --------------------------
# Port Scanner
# --------------------------
def scan_port(target, port, timeout=1):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        if result == 0:
            try:
                service = socket.getservbyport(port)
            except OSError:
                service = "unknown"

            banner = grab_banner(target, port)
            risk = classify_risk(port, service, banner)

            return {
                "port": port,
                "service": service,
                "banner": banner,
                "risk": risk
            }

    except socket.timeout:
        logging.debug(f"Timeout on port {port}")
    except socket.gaierror:
        logging.error(f"DNS resolution failed for {target}")
    except OSError as e:
        logging.debug(f"OS error on port {port}: {e}")
    finally:
        sock.close()

    return None

# --------------------------
# Banner Grabbing
# --------------------------
def grab_banner(ip, port):
    sock = socket.socket()
    sock.settimeout(1)

    try:
        sock.connect((ip, port))
        data = sock.recv(1024)
        return data.decode(errors="ignore").strip()

    except socket.timeout:
        logging.debug(f"Banner grab timeout on {port}")
    except ConnectionRefusedError:
        logging.debug(f"Connection refused on banner grab {port}")
    except OSError as e:
        logging.debug(f"Banner grab failed on {port}: {e}")
    finally:
        sock.close()

    return None

# --------------------------
# HTTP Check
# --------------------------
def http_check(target):
    try:
        r = requests.get(f"http://{target}", timeout=2)
        return r.headers.get("Server", "Unknown")

    except requests.exceptions.Timeout:
        logging.debug("HTTP request timeout")
    except requests.exceptions.ConnectionError:
        logging.debug("HTTP connection error")
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP error: {e}")

    return None

# --------------------------
# Generate HTML Report
# --------------------------
def generate_report(results, target, output_file):
    template = """
    <html>
    <head><title>Security Scan Report</title></head>
    <body>
    <h1>Security Report for {{ target }}</h1>
    <p>Date: {{ date }}</p>
    <h2>Open Ports</h2>
    <ul>
    {% for r in results %}
      <li>{{ r.port }}/tcp - {{ r.service }}{% if r.banner %} ({{ r.banner }}){% endif %}<strong>[{{ r.risk }}]</strong></li>
    {% endfor %}
    </ul>
    </body>
    </html>
    """
    t = Template(template)
    html = t.render(
        results=results,
        target=target,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    )

    with open(output_file, "w") as f:
        f.write(html)

# --------------------------
# Main
# --------------------------
def main():
    parser = argparse.ArgumentParser(description="Mini Security Scanner")
    parser.add_argument("--target", required=True, help="Target IP or domain")
    parser.add_argument("--output", default="report.html", help="Output report file")
    args = parser.parse_args()

    target = args.target
    logging.info(f"Starting scan on {target}")

    results = []

    for port in range(20, 1025):
        scan = scan_port(target, port)
        if scan:
            logging.info(
                f"OPEN {scan['port']}/tcp "
                f"{scan['service']} "
                f"Risk={scan['risk']} "
                f"{scan['banner'] or ''}"
            )

            results.append(scan)

    server_header = http_check(target)
    if server_header:
        results.append({
            "port": 80,
            "service": "http",
            "banner": server_header,
            "risk": classify_risk(80, "http", server_header)
        })

    with open("results.json", "w") as f:
        json.dump(results, f, indent=4)

    generate_report(results, target, args.output)
    logging.info(f"Report saved to {args.output}")

if __name__ == "__main__":
    main()
