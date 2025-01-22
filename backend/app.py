from flask import Flask, jsonify, request
import nmap  # or scapy for network scanning

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"message": "Hello, Flask with nmap!"})

@app.route('/scan', methods=['POST'])
def scan_network():
    nm = nmap.PortScanner()
    nm.scan('192.168.1.0/24')  # Adjust the network range as needed
    results = []
    for host in nm.all_hosts():
        results.append({
            'host': host,
            'state': nm[host].state(),
            'protocols': nm[host].all_protocols()
        })
    return jsonify({"message": "Scan complete", "results": results})

@app.route('/results', methods=['GET'])
def get_results():
    # For simplicity, return a static response
    return jsonify([{"host": "192.168.1.1", "state": "up", "protocols": ["tcp", "udp"]}])

if __name__ == '__main__':
    app.run(debug=True)