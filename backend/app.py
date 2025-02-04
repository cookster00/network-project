from flask import Flask, jsonify, request
import nmap  # or scapy for network scanning

app = Flask(__name__)

@app.route('/')
def home():
    return jsonify({"message": "Hello, Flask with nmap!"})

@app.route('/scan', methods=['POST'])
def scan_network():
    print('scanning netwro')
    nm = nmap.PortScanner()
    nm.scan('127.0.0.1')  # Scanning local machine
    results = []
    for host in nm.all_hosts():
        host_info = {
            'host': host,
            'state': nm[host].state(),
            'protocols': []
        }
        for proto in nm[host].all_protocols():
            protocol_info = {
                'protocol': proto,
                'ports': []
            }
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                protocol_info['ports'].append({
                    'port': port,
                    'state': nm[host][proto][port]['state']
                })
            host_info['protocols'].append(protocol_info)
        results.append(host_info)
    return jsonify({"message": "Scan complete", "results": results})

@app.route('/results', methods=['GET'])
def get_results():
    # For simplicity, return a static response
    return jsonify([{"host": "192.168.1.1", "state": "up", "protocols": ["tcp", "udp"]}]) 

@app.errorhandler(400)
def bad_request(error):
    app.logger.error(f"Bad Request: {request.data}")
    return jsonify({"error": "Bad Request"}), 400

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {error}")
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    app.run(debug=True)