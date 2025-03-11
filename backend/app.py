from flask import Flask, jsonify, request
from flask_cors import CORS
import nmap  # or scapy for network scanning

from scan import scan_network, scan_ftp, scan_smb, scan_dns, scan_vulns, scan_snmp, scan_ports, calc_score

app = Flask(__name__)

CORS(app)

@app.route('/')
def home():
    return jsonify({"message": "Hello, Flask with nmap!"})

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    app.logger.info(f"IP Address: {ip}")

    # Scan the network
    results = scan_network(ip)

    return jsonify({"message": "Scan complete", "results": results})

@app.route('/ftp_scan', methods=['POST'])
def ftp_scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    ftp_results = scan_ftp(ip)

    return jsonify({"message": "FTP Scan complete", "results": ftp_results})

@app.route('/smb_scan', methods=['POST'])
def smb_scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    smb_results = scan_smb(ip)

    return jsonify({"message": "SMB Scan complete", "results": smb_results})

@app.route('/dns_scan', methods=['POST'])
def dns_scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    dns_results = scan_dns(ip)

    return jsonify({"message": "DNS Scan complete", "results": dns_results})

@app.route('/vulns_scan', methods=['POST'])
def vulns_scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    vulns_results = scan_vulns(ip)

    return jsonify({"message": "Vulns Scan complete", "results": vulns_results})


@app.route('/snmp_scan', methods=['POST'])
def snmp_scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    snmp_results = scan_snmp(ip)

    return jsonify({"message": "SNMP Scan complete", "results": snmp_results})


@app.route('/port_scan', methods=['POST'])
def port_scan():
    data = request.get_json()
    ip = data.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    port_results = scan_ports(ip)

    return jsonify({"message": "Port Scan complete", "results": port_results})

@app.route('/get_score', methods=['POST'])
def get_score():
    data = request.get_json()
    ftp = data.get('ftp')
    smb = data.get('smb')
    dns = data.get('dns')
    vulns = data.get('vulns')
    snmp = data.get('snmp')

    score = calc_score(ftp, smb, dns, vulns, snmp)

    return jsonify({"message": "Score calculated", "score": score})

@app.errorhandler(400)
def bad_request(error):
    app.logger.error(f"Bad Request: {request.data}")
    return jsonify({"error": "Bad Request"}), 400

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {error}")
    return jsonify({"error": "Internal Server Error"}), 500

@app.before_request
def log_request_info():
    app.logger.debug('Headers: %s', request.headers)
    app.logger.debug('Body: %s', request.get_data())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)