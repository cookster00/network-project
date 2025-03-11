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


    # Calculate the score
    score = calc_score(ftp, smb, dns, vulns, snmp)



    results = {
        'ftp': ftp,
        'smb': smb,
        'dns': dns,
        'vulns': vulns,
        'snmp': snmp,
        'ports': ports,
        'score': score
    }

    return results

def scan_ftp(IP):
    ''' ftp vulnerability scan '''

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    nm.scan(hosts=f'{IP}', arguments='--script=ftp-anon -p 21')


    # Parsing results
    if "21" in nm[IP]["tcp"]:
        ftp_info = nm[IP]["tcp"][21]

        if "script" in ftp_info and "ftp-anon" in ftp_info["script"]:
            results = (True, ftp_info["script"]["ftp-anon"])
        else:
            results = (False, "FTP Anonymous Access is not Allowed")
    else:
        results = (False, "Port 21 is closed or filtered, no chance of Anonymous FTP Access.")

    return results

def scan_smb(IP):
    ''' smb vulnerability scan '''

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    nm.scan(hosts=f'{IP}', arguments='--script=smb-enum-shares -p 445')


    # Parsing results
    if "445" in nm[IP]["tcp"]:
        smb_info = nm[IP]["tcp"][445]

        if "script" in smb_info and "smb-enum-shares" in smb_info["script"]:
            results = (True, smb_info["script"]["smb-enum-shares"])
        else:
            results = (False, "No Exposed SMB Shares Found.")
    else:
        results = (False, "Port 445 is closed or filtered, no chance of exposed SMB Shares.")

    return results

def scan_dns(IP):
    ''' dns vulnerability scan '''

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    nm.scan(hosts=f'{IP}', arguments='--script=dns-zone-transfer -p 53')


    # Parsing results
    if "53" in nm[IP]["tcp"]:
        dns_info = nm[IP]["tcp"][53]

        if "script" in dns_info and "dns-zone-transfer" in dns_info["script"]:
            results = (True, dns_info["script"]["dns-zone-transfer"])
        else:
            results = (False, "DNS Zone Transfer Not Allowed or No Data Found.")
    else:
        results = (False, "Port 53 is closed or filtered, no chance of DNS Zone Transfer.")

    return results

def scan_vulns(IP):
    ''' Vulnerability scan '''

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    nm.scan(hosts=f'{IP}', arguments='--script=vulners -sV')


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

def scan_snmp(IP):
    ''' snmp vulnerability scan '''

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    nm.scan(hosts=f'{IP}', arguments="--script=snmp-brute -p 161")

    # Parsing results
    if "udp" in nm[IP] and 161 in nm[IP]["udp"]:
        snmp_info = nm[IP]["udp"][161]

        if "script" in snmp_info and "snmp-brute" in snmp_info["script"]:
            results = (True, snmp_info["script"]["snmp-brute"])
        else:
            results = (False, "SNMP Brute Force Failed.")
    else:
        results = (False, "Port 161 is closed or filtered, no chance of SNMP misconfigurations.")

    return results 

def scan_ports(IP):
    ''' Scan all open ports and their states '''

    # Initialize the nmap PortScanner
    nm = nmap.PortScanner()
    nm.scan(hosts=f'{IP}', arguments='-p-')  # Scan all ports

    # Parsing results
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

def calc_score(ftp, smb, dns, vulns, snmp):
    ''' Calculate the score based on the vulnerabilities found '''
    total_vulns = 0

    # Count quantity of vulnerabilities
    if ftp[0]:
        total_vulns += 1
    if smb[0]:
        total_vulns += 1  
    if dns[0]:  
        total_vulns += 1
    if snmp[0]:
        total_vulns += 1
    
    for port in vulns[1]:
        if port['vulnerabilities'] != 'No vulnerabilities found.':
            total_vulns += len(port['vulnerabilities'])

    # Calculate the score
    score = 100 * (0.9 ** total_vulns)

    return score