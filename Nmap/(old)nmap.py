#!/usr/bin/env python3

# nmap scan and pentest

import csv
import sys
from datetime import datetime
import subprocess
import nmap

#check what system this operating system is running
sys_vers = sys.platform


# get current time

time = datetime.now()
formatted_time = time.strftime("%Y-%m-%d-%H-%M")

# find size of network

def network(sys_vers): 
    if sys_vers == 'linux':
        grep_inet = ["ip a | grep -Eo '\\b([0-9]{1,3}\\.){3}[0-9]{1,3}/[0-9]+\\sbrd\\s\\b'"]
        ip_addr_net_mask = subprocess.run(grep_inet, shell=True, text=True, capture_output=True, check=True)
        return ip_addr_net_mask.stdout.strip().replace(' brd','')    
    else: 
        print('unsupported distro')

# do the network scan
def network_scanner(ip_address):
    host = ip_address
    ns = nmap.PortScanner()
    network_data = {}

    try: 
        #gather all hosts that are openand and that are scanned
        ns.scan(hosts = host, arguments='-T5 -p 1-65535 -sV -O -sT -A -Pn ') 

        for host in ns.all_hosts():
            if ns[host].state() == "up" or ns[host].state() == "down":
                host_data = {
                    'hostname': ns[host].hostname(),
                    'state': ns[host].state(),
                    'protocols': {},
                    'os_info': []
                }

        #gather the ports, the state, the service, and the version to then store in the corresponding ip addresses dictionary
    
            for proto in ns[host].all_protocols():
                host_data['protocols'][proto] = []
                lport = sorted(ns[host][proto].keys())
                for port in lport:
                    port_info = ns[host][proto][port]
                    port_data = {
                        'port': port,
                        'state': port_info['state'],
                        'service': port_info['name'],
                        'product': port_info['product'],
                        'version': port_info['version'],
                    }
                    host_data['protocols'][proto].append(port_data)

        #gather the opearting system information
            if 'osclass' in ns[host]:
                for osclass in ns[host]['osclass']:
                    os_info.append({
                        'vendor': osclass['vendor'],
                        'osfamily': osclass['osfamily'],
                        'osgen': osclass['type'],
                        'accuracy': osclass['accruracy']
                    })
    

        #add this host's data to network dictionary
        network_data[host] = host_data

        return network_data

        
          
    except Exception as e:
        print(e)


#this function flattens the data and makes one dictionary to input the data into one line on the csv
def flatten_host_data(host_data):
    rows = []
    for host, details in host_data.items():
        hostname = details.get('hostname', 'N/A')
        state = details.get('state', 'N/A')

        for proto, ports in details.get('protocols', {}).items():
            for port_info in ports:
                port = port_info.get('port', 'N/A')
                port_state = port_info.get('state', 'N/A')
                service = port_info.get('service', 'N/A')
                product = port_info.get('product', 'N/A')
                version = port_info.get('version', 'N/A')
                if details.get('os_info'):
                    for osclass in details['os_info']:
                        row = {
                            'host': host,
                            'hostname': hostname,
                            'state': state,
                            'protocol': proto,
                            'port': port,
                            'port_state': port_state,
                            'service': service,
                            'product': product,
                            'version': version,
                            'vendor': osclass.get('vendor', 'N/A'),
                            'osfamily': osclass.get('osfamily', 'N/A'),
                            'osgen': osclass.get('osgen', 'N/A'),
                            'accuracy': osclass.get('accuracy', 'N/A')
                        }
                        rows.append(row)
                else:
                    row = {
                        'host': host,
                        'hostname': hostname,
                        'state': state,
                        'protocol': proto,
                        'port': port,
                        'port_state': port_state,
                        'service': service,
                        'product': product,
                        'version': version,
                        'vendor': 'N/A',
                        'osfamily': 'N/A',
                        'osgen': 'N/A',
                        'accuracy': 'N/A'
                    }
                    rows.append(row)
    return rows


host = network(sys_vers)
network_ip = host.split()
target = input("Do you want to scan your network or a target's network? (1/2): ")
if target == '1':
    host_data = network_scanner(network_ip[0].replace("'", ""))
elif target == '2':
    target_ip = input("Enter the targets ip and or cidr notation: ")
    host_data = network_scanner(target_ip)
rows = flatten_host_data(host_data)

#define csv file headers
headers = ['host', 'hostname', 'state', 'protocol', 'port', 'port_state', 'service', 'product', 'version', 'vendor', 'osfamily', 'osgen', 'accuracy']

# write to csv file 
with open(f'{formatted_time}_nmap_scan.csv', 'w', newline='') as csvfile: 
    writer = csv.DictWriter(csvfile, fieldnames=headers)
    writer.writeheader()
    writer.writerows(rows)

print("All Done:)")





