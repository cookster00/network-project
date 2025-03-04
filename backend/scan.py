# File for all scanning related functions

import os
import socket
import nmap

def scan_network(IP):
    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    
    # Vulnerability 1: FTP Anonymous Login
    nm.scan(hosts=f'{IP}', arguments='--script=ftp-anon -p 21')
    ftp = ftp_results(nm, IP)

    # Vulnerability 2: SMB Shares
    nm.scan(hosts=f'{IP}', arguments='--script=smb-enum-shares -p 445')
    smb = smb_results(nm, IP)

    # Vulnerability 3: DNS Zone Transfer
    nm.scan(hosts=f'{IP}', arguments='--script=dns-zone-transfer -p 53')
    dns = dns_results(nm, IP)

    # Vulnerability 4: Outdated Software
    nm.scan(hosts=f'{IP}', arguments='--script=vulners -sV')
    vulns = vulns_results(nm, IP)

    # Vulnerability 5: SNMP Misconfiguration
    nm.scan(hosts=f'{IP}', arguments="--script=snmp-brute -p 161")
    snmp = snmp_results(nm, IP)

    # Scan for all open ports and their states
    nm.scan(hosts=f'{IP}', arguments='-p-')  # Scan all ports
    ports = port_results(nm, IP)



    results = {
        'ftp': ftp,
        'smb': smb,
        'dns': dns,
        'vulns': vulns,
        'snmp': snmp,
        'ports': ports
    }

    # Perform a vulnerability scan on the target IP
    # nm.scan(hosts=f'{IP}', arguments='--script=vulners -sV')
    # results = parse_scan_results(nm)

    # Perform an SMB OS discovery scan on the target IP
    # nm.scan(hosts=f'{IP}', arguments='--script=smb-os-discovery.nse')
    # smb_results = parse_scan_results(nm)

    # Combine the results from both scans
    # combined_results = combine_scan_results(results, smb_results)

    return results

def ftp_results(nm, IP):
    ''' Parsing results from ftp vulnerability scan '''
    if "21" in nm[IP]["tcp"]:
        ftp_info = nm[IP]["tcp"][21]

        if "script" in ftp_info and "ftp-anon" in ftp_info["script"]:
            results = (True, ftp_info["script"]["ftp-anon"])
        else:
            results = (False, "FTP Anonymous Access is not Allowed")
    else:
        results = (False, "FTP port (21) is closed or filtered.")

    return results

def smb_results(nm, IP):
    ''' Parsing results from smb vuln scan '''
    # Check if the target has an open SMB port
    if "445" in nm[IP]["tcp"]:
        smb_info = nm[IP]["tcp"][445]

        if "script" in smb_info and "smb-enum-shares" in smb_info["script"]:
            results = (True, smb_info["script"]["smb-enum-shares"])
        else:
            results = (False, "No Exposed SMB Shares Found.")
    else:
        print("\n[-] SMB port (445) is closed or filtered.")
        results = (False, "SMB port (445) is closed or filtered")

    return results

def dns_results(nm, IP):
    ''' Parsing results from dns zone transfer scan '''
    if "53" in nm[IP]["tcp"]:
        dns_info = nm[IP]["tcp"][53]

        if "script" in dns_info and "dns-zone-transfer" in dns_info["script"]:
            results = (True, dns_info["script"]["dns-zone-transfer"])
        else:
            results = (False, "DNS Zone Transfer Not Allowed or No Data Found.")
    else:
        results = (False, "DNS port (53) is closed or filtered.")

    return results

def vulns_results(nm, IP):
    ''' Parsing results from vulners scan '''
    vulnerabilities = []

    if IP in nm.all_hosts():
        for port, port_info in nm[IP]['tcp'].items():
            if 'script' in port_info and 'vulners' in port_info['script']:
                vuln = port_info['script']['vulners'].split("\n")
                vulnerabilities.append({
                    'port': port,
                    'service' : port_info['name'],
                    'vulnerabilities': vuln
                })
            else:
                vulnerabilities.append({
                    'port': port,
                    'service' : port_info['name'],
                    'vulnerabilities': 'No vulnerabilities found.'
                })

        results = (True, vulnerabilities)
    else:
        results = (False, "No open ports found or scan was blocked.")
    
    return results

def snmp_results(nm, IP):
    ''' Parsing results from snmp scan '''
    if "udp" in nm[IP] and 161 in nm[IP]["udp"]:
        snmp_info = nm[IP]["udp"][161]

        if "script" in snmp_info and "snmp-brute" in snmp_info["script"]:
            results = (True, snmp_info["script"]["snmp-brute"])
        else:
            results = (False, "SNMP Brute Force Failed.")
    else:
        results = (False, "SNMP port (161) is closed or filtered.")

    return results 

def port_results(nm, IP):
    ''' Parsing results from port scan '''
    port_info = []
    for proto in nm[IP].all_protocols():
        lport = nm[IP][proto].keys()
        for port in lport:
            port_info.append({
                'port': port,
                'state': nm[IP][proto][port]['state'],
                'service': nm[IP][proto][port].get('name', '')
            })
    return port_info


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