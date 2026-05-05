from flask import Flask, render_template, request, jsonify
import subprocess
import socket
import requests
import ssl
import tempfile
import ipaddress
import os
import re
from urllib.parse import urlparse
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# Home page
@app.route("/")
def index():
    return render_template("index.html")

#Input Validation for IP
def is_safe_host(host):
    try:
        # If it's already an IP
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            # resolve domain to IP
            resolved_ip = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved_ip)

        # Block ALL internal / unsafe ranges
        if (
            ip.is_private or
            ip.is_loopback or
            ip.is_reserved or
            ip.is_link_local or
            ip.is_multicast
        ):
            return False

        return True

    except Exception:
        return False

#Input validation for URL
def is_safe_url(url):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ["http", "https"]:
            return False

        if not parsed.hostname:
            return False

        return is_safe_host(parsed.hostname)

    except Exception:
        return False


# Ping
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host")


    if not host:
        return jsonify({"error": "No host provided"}), 400

    if not is_safe_host(host):
        return jsonify({"error": "Invalid or blocked host"}), 400

    try:
        cmd = ["ping", "-c", "4", host] if subprocess.os.name != "nt" else ["ping", "-n", "4", host]

        result = subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10
        )

        return result

    except subprocess.TimeoutExpired:
        return jsonify({"error": "Ping timed out"}), 504

    except Exception:
        return jsonify({"error": "Ping failed"}), 500


# Traceroute
@app.route("/tracert", methods=["POST"])
def tracert():
    host = request.json.get("host")

    # ✅ ADD THIS BLOCK HERE (IMPORTANT)
    if not host or not is_safe_host(host):
        return jsonify({"error": "Invalid or blocked host"}), 400

    command = "tracert" if subprocess.os.name == "nt" else "traceroute"

    try:
        result = subprocess.check_output(
            [command, host],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        return result

    except Exception as e:
        return jsonify({"error": "Traceroute failed"}), 500


# NSLookup
@app.route("/nslookup", methods=["POST"])
def nslookup():
    host = request.json.get("host")

    if not host or not is_safe_host(host):
        return jsonify({"error": "Invalid or blocked host"}), 400
    try:
        result = subprocess.check_output(
            ["nslookup", host],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        return result
    except Exception as e:
        return str(e)


# Port Scan
@app.route("/portscan", methods=["POST"])
def portscan():

    if not request.is_json:
        return jsonify({"error": "JSON required"}), 400

    host = request.json.get("host")

    if not host or not is_safe_host(host):
        return jsonify({"error": "Invalid or blocked host"}), 400

    try:
        ip = socket.gethostbyname(host)

        if not is_safe_host(ip):
            return jsonify({"error": "Blocked IP"}), 400

        common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]

        open_ports = []

        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)

            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)

            sock.close()

        return jsonify({
            "host": host,
            "ip": ip,
            "open_ports": open_ports
        })

    except Exception as e:
        app.logger.error(str(e))
        return jsonify({"error": "Port scan failed"}), 500


# GeoIP Lookup
@app.route("/geoip", methods=["POST"])
def geoip():
    host = request.json.get("host")

    if not host or not is_safe_host(host):
        return jsonify({"error": "Invalid or blocked host"}), 400
    try:
        res = requests.get(f"http://ip-api.com/json/{host}").json()
        return "\n".join([f"{k}: {v}" for k, v in res.items()])
    except Exception as e:
        return str(e)


# HTTP Headers
@app.route("/http_headers", methods=["POST"])
def http_headers():
    url = request.json.get("url")
    if not url or not is_safe_url(url):
        return jsonify({"error": "Invalid or unsafe URL"}), 400
    try:
        headers = requests.get(url, timeout=5).headers
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])
    except Exception as e:
        return str(e)


# SSL Check
@app.route("/ssl_check", methods=["POST"])
def ssl_check():
    host = request.json.get("host")

    if not host or not is_safe_host(host):
        return jsonify({"error": "Invalid or blocked host"}), 400

    try:
        cert = ssl.get_server_certificate((host, 443))

        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pem") as f:
            f.write(cert)
            f.flush()
            cert_path = f.name

        x509 = ssl._ssl._test_decode_cert(cert_path)

        output = f"Issuer: {x509.get('issuer')}\n"
        output += f"Subject: {x509.get('subject')}\n"
        output += f"Valid From: {x509.get('notBefore')}\n"
        output += f"Valid To: {x509.get('notAfter')}\n"

        os.remove(cert_path)

        return output

    except Exception as e:
        return str(e)


if __name__ == "__main__":
    app.run(debug=False)