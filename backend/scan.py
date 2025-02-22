# File for all scanning related functions

import socket
import nmap

def scan_network(IP):
    # Scans given IP and returns the results of scan 
    nm = nmap.PortScanner()
    nm.scan(IP)
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
    return results

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Connects to Google DNS but doesn't send data
    ip = s.getsockname()[0]
    s.close()
    return ip