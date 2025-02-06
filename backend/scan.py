# File for all scanning related functions


import nmap

def scan_network(IP):

    nm = nmap.PortScanner()
    nm.scan(IP)  # Scanning local machine
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

    return