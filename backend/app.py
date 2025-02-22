from flask import Flask, jsonify, request
from flask_cors import CORS
import nmap  # or scapy for network scanning
import socket


from scan import scan_network, get_ip

app = Flask(__name__)

CORS(app)

@app.route('/')
def home():
    return jsonify({"message": "Hello, Flask with nmap!"})

@app.route('/scan', methods=['POST'])
def scan():
    # Scans network (currently the local machine) and returns state, protocols and ports

    # Grabbing Network IP from users machine
    IP = get_ip()


    # Scan the network
    # results = scan_network(IP)
    results = IP

    return jsonify({"message": "Scan complete", "results": results})

@app.errorhandler(400)
def bad_request(error):
    app.logger.error(f"Bad Request: {request.data}")
    return jsonify({"error": "Bad Request"}), 400

@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f"Internal Server Error: {error}")
    return jsonify({"error": "Internal Server Error"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)