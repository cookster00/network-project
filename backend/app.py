from flask import Flask, jsonify, request
from flask_cors import CORS
import nmap  # or scapy for network scanning

from scan import scan_network

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