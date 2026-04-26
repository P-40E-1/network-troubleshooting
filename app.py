from flask import Flask, render_template, request, jsonify
import subprocess
import socket
import requests
import ssl
import tempfile
from datetime import datetime
from urllib.parse import urlparse

app = Flask(__name__)

# Home page
@app.route("/")
def index():
    return render_template("index.html")


# Ping
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host")
    try:
        result = subprocess.check_output(
            ["ping", "-n" if subprocess.os.name == "nt" else "-c", "4", host],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        return result
    except Exception as e:
        return str(e)


# Traceroute
@app.route("/tracert", methods=["POST"])
def tracert():
    host = request.json.get("host")
    command = "tracert" if subprocess.os.name == "nt" else "traceroute"
    try:
        result = subprocess.check_output(
            [command, host],
            stderr=subprocess.STDOUT,
            universal_newlines=True
        )
        return result
    except Exception as e:
        return str(e)


# NSLookup
@app.route("/nslookup", methods=["POST"])
def nslookup():
    host = request.json.get("host")
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
    host = request.json.get("host")
    common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]
    output = f"Scanning {host}...\n\n"

    try:
        ip = socket.gethostbyname(host)
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                output += f"[OPEN] Port {port}\n"
            sock.close()
        return output
    except Exception as e:
        return str(e)


# GeoIP Lookup
@app.route("/geoip", methods=["POST"])
def geoip():
    host = request.json.get("host")
    try:
        res = requests.get(f"http://ip-api.com/json/{host}").json()
        return "\n".join([f"{k}: {v}" for k, v in res.items()])
    except Exception as e:
        return str(e)


# HTTP Headers
@app.route("/http_headers", methods=["POST"])
def http_headers():
    url = request.json.get("url")
    try:
        headers = requests.get(url, timeout=5).headers
        return "\n".join([f"{k}: {v}" for k, v in headers.items()])
    except Exception as e:
        return str(e)


# SSL Check
@app.route("/ssl_check", methods=["POST"])
def ssl_check():
    host = request.json.get("host")
    try:
        cert = ssl.get_server_certificate((host, 443))

        with tempfile.NamedTemporaryFile(delete=False, mode="w", suffix=".pem") as f:
            f.write(cert)
            cert_path = f.name

        x509 = ssl._ssl._test_decode_cert(cert_path)

        output = f"Issuer: {x509.get('issuer')}\n"
        output += f"Subject: {x509.get('subject')}\n"
        output += f"Valid From: {x509.get('notBefore')}\n"
        output += f"Valid To: {x509.get('notAfter')}\n"

        return output
    except Exception as e:
        return str(e)


if __name__ == "__main__":
    app.run(debug=True)