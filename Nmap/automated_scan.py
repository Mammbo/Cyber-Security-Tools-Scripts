#!/usr/bin/python3

import subprocess
import shlex 
import os 
import sys 
import xml.etree.ElementTree as ET
from datetime import datetime 

time = datetime.now()
formatted_time = time.strftime("%Y/%m/%d_%H-%M")

# root check 
def root(): 
    if os.getuid() == 0: 
        return True
    else: 
        return False

# uid and gid check to set the owner of the file to your user 

def makeOwner(path):
    uid = os.environ.get('SUDO_UID')
    gid = os.environ.get('SUDO_GID')
    if uid is not None:
        os.chown(path, int(uid), int(gid))

def parseDiscoverXml(in_xml):
    live_hosts = []
    xml_tree = ET.parse(in_xml)
    xml_root = xml_tree.getroot()
    for host in xml_root.findall('host'):
        ip_state = host.find('status').get('state')
        if ip_state == "up":
            live_hosts.append(host.find('address').get('addr'))
    return live_hosts


def convertToNmapTarget(hosts):
    hosts = list(dict.fromkeys(hosts))
    return " ".join(hosts)

def parseDiscoverPorts(in_xml):
    results = []
    port_list = ''
    xml_tree = ET.parse(in_xml)
    xml_root = xml_tree.getroot()
    for host in xml_root.findall('host'):
        ip = host.find('address').get('addr')
        ports = host.findall('ports')[0].findall('port')
        for port in ports:
            state = port.find('state').get('state')
            if state == 'open':
                port_list += port.get('portid') + ','
        port_list = port_list.rstrip(',')
        if port_list:
            results.append(f"{ip} {port_list}")
        port_list = ''
    return results


#host discovery 
def icmp_echo_host_scan(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}icmp_echo_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PE -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)
 
def icmp_netmask_host_scan(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}icmp_netmask_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PM -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)

def icmp_timestamp_host_scan(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}icmp_timestamp_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PP -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)

def tcp_syn_host_scan(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}tcp_syn_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -PS21,22,23,25,80,113,443 -PA80,113,443 -n -sn -T4 -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)

#port scanning (1000)

def tcpsyn_port_scan_1000(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml,f'{formatted_time}top_1000_portscan.xml')
    nmap_cmd = f"/usr/bin/nmap {target} --top-ports 1000 -n -Pn -sS -T4 --min-parallelism 100 --min-rate 64 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeOwner(out_xml)

#service detection 
def service_scan(target_ip, target_ports, out_xml, formatted_time):
    out_xml = os.path.join(out_xml,f'{formatted_time}-{target_ip}_services.xml')
    nmap_cmd = f"/usr/bin/nmap {target_ip} -p {target_ports} --exclude-ports 9100-9107, 515, 1028, 1068, 1503, 1720, 1935, 2040, 3388 -n -Pn -sV --version-intensity 6 --script banner -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

#os detection 

def os_scan(targets, out_xml, formatted_time):
    out_xml = os.path.join(out_xml,f'{formatted_time}osdetection.xml')
    nmap_cmd = f"/usr/bin/nmap {targets} -n -Pn -O -T4 --min-parallelism 100 --min-rate 64 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeOwner(out_xml)


# ssl ciphers
def ssl_cipher_scan(target_ip, target_ports, out_xml, formatted_time):
    out_xml = os.path.join(out_xml,f'{formatted_time}--{target_ip}_ssl_ciphers.xml')
    nmap_cmd = f"/usr/bin/nmap {target_ip} -p {target_ports} -n -Pn --script ssl-enum-ciphers -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()


#ssl certs 
def ssl_cert_scan(target_ip, target_ports, out_xml, formatted_time):
    out_xml = os.path.join(out_xml,f'{formatted_time}--{target_ip}_ssl_certs.xml')
    nmap_cmd = f"/usr/bin/nmap {target_ip} -p {target_ports} -n -Pn --script ssl-cert -T4 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
#all ports scan 

def tcp_syn_port_scan_all(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml,f'{formatted_time}65535_portscan.xml')
    nmap_cmd = f"/usr/bin/nmap {target} -p- -n -Pn -sS -T4 --min-parallelism 100 --min-rate 128 -vv -oX {out_xml}"
    sub_args = shlex.split(nmap_cmd)
    subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    makeOwner(out_xml)

# ask for input of who is the target 
# if trying to automate set the ip address to run the scan 


def main():
    if not root():
        print('[!] Root Privellages are required for this program to run')
        sys.exit(1)
    
    target = ''

    icmp_echo_host_scan(target, os.getcwd())
    icmp_netmask_host_scan(target, os.getcwd())
    icmp_timestamp_host_scan(target, os.getcwd())
    tcp_syn_host_scan(target, os.getcwd())


    hosts = parseDiscoverXml('any dir')
    hosts += parseDiscoverXml('any dir')
    hosts += parseDiscoverXml('any dir')
    hosts += parseDiscoverXml('any dir')

    target = convertToNmapTarget(hosts)

    targets = parseDiscoverPorts('anydir/top_1000_portscan.xml')
    for target in targets:
        element = target.split()
        target_ip = element[0]
        target_ports = element[1]
        print(f'Nmap Format Example: nmap {target_ip} -p {target_ports}')

    tcpsyn_port_scan_1000(target, os.getcwd(), formatted_time)
    service_scan(target_ip, target_ports, os.getcwd(), formatted_time)
    os_scan(targets, os.getcwd(), formatted_time)
    ssl_cipher_scan(target_ip, target_ports, os.getcwd(), formatted_time)
    ssl_cert_scan(target_ip, target_ports, os.getcwd(), formatted_time)
    tcp_syn_port_scan_all(target, os.getcwd(), formatted_time)
    
if __name__ == '__main__':
    main()

