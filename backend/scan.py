# File for all scanning related functions

import socket
import nmap

def scan_network(IP):
    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    
    # Perform a vulnerability scan on the target IP
    nm.scan(hosts=f'{IP}', arguments='--script=vulners -sV')
    results = parse_scan_results(nm)

    # Perform an SMB OS discovery scan on the target IP
    nm.scan(hosts=f'{IP}', arguments='--script=smb-os-discovery.nse')
    smb_results = parse_scan_results(nm)

    # Combine the results from both scans
    combined_results = combine_scan_results(results, smb_results)
    
    return combined_results

def parse_scan_results(nm):
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
                    'state': nm[host][proto][port]['state'],
                    'service': nm[host][proto][port].get('name', ''),
                    'version': nm[host][proto][port].get('version', ''),
                    'vulnerabilities': nm[host][proto][port].get('script', {}).get('vulners', ''),
                    'smb_os_discovery': nm[host][proto][port].get('script', {}).get('smb-os-discovery', '')
                })
            host_info['protocols'].append(protocol_info)
        results.append(host_info)
    return results

def combine_scan_results(results, smb_results):
    # Combine the results from both scans
    combined_results = results
    for smb_result in smb_results:
        for result in combined_results:
            if smb_result['host'] == result['host']:
                for proto in smb_result['protocols']:
                    for port in proto['ports']:
                        for res_proto in result['protocols']:
                            if res_proto['protocol'] == proto['protocol']:
                                for res_port in res_proto['ports']:
                                    if res_port['port'] == port['port']:
                                        res_port['smb_os_discovery'] = port['smb_os_discovery']
    return combined_results

def get_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))  # Connects to Google DNS but doesn't send data
    ip = s.getsockname()[0]
    s.close()
    return ip