from flask import Flask, render_template, request
import subprocess

app = Flask(__name__)

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/ping', methods=['POST'])
def ping():
    host = request.form['host']
    result = subprocess.run(
        ['ping', '-n', '4', host],  # use -c on Linux
        capture_output=True,
        text=True
    )
    return render_template('result.html', output=result.stdout)


@app.route('/tracert', methods=['POST'])
def tracert():
    host = request.form['host']
    result = subprocess.run(['tracert', host], capture_output=True, text=True)
    return render_template('result.html', output=result.stdout)

@app.route('/nslookup', methods=['POST'])
def nslookup():
    host = request.form['host']
    result = subprocess.run(['nslookup', host], capture_output=True, text=True)
    return render_template('result.html', output=result.stdout)

@app.route('/myip')
def myip():
    ip = request.remote_addr
    return render_template('result.html', output=f"Your IP: {ip}")

import socket

@app.route('/reverse_dns', methods=['POST'])
def reverse_dns():
    ip = request.form['host']
    try:
        hostname = socket.gethostbyaddr(ip)
        output = hostname[0]
    except:
        output = "No PTR record found."
    return render_template('result.html', output=output)

import socket

@app.route('/portscan', methods=['POST'])
def portscan():
    host = request.form['host']
    ports = [21, 22, 80, 443, 3306]
    output = ""
    for port in ports:
        s = socket.socket()
        s.settimeout(1)
        result = s.connect_ex((host, port))
        if result == 0:
            output += f"Port {port} is OPEN\n"
        else:
            output += f"Port {port} is CLOSED\n"
        s.close()
    return render_template('result.html', output=output)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)