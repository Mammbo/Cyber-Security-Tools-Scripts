#!/usr/bin/python3

import subprocess
import shlex 
import os 
import sys 
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


#host discovery 
def icmp_echo_host_discovery(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}icmp_echo_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PE -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)
 
def icmp_netmask_host_discovery(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}icmp_netmask_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PE -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)

def icmp_timestamp_host_discovery(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}icmp_timestamp_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PE -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)

def tcp_syn_host_discovery(target, out_xml, formatted_time):
    out_xml = os.path.join(out_xml, f"{formatted_time}tcp_syn_host_discovery.xml")
    nmap_command = f"/usr/bin/nmap {target} -n -sn -PE -vv -oX {out_xml}"
    nmap_args = shlex.split(nmap_command)
    subprocess.Popen(nmap_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE.communicate())
    makeOwner(out_xml)


#make myself the owner of the file using uid and guid of who is runing the process 

# make sure I am running this in root  by getting the uid and guid 

# make sure i get CWD 
#port scanning (1000)

#service detection 

#os detection 

# ssl ciphers

#ssl certs 

#all ports scan 



# ask for input of who is the target 
# if trying to automate set the ip address to run the scan 


def main():
    if not root():
        print('[!] The discovery probes in this script requires root privileges')
        sys.exit(1)
    
    target = '192.'

    icmp_echo_host_discovery(target, os.getcwd)
    icmp_netmask_host_discovery(target, os.getcwd)
    icmp_timestamp_host_discovery(target, os.getcwd)
    tcp_syn_host_discovery(target, os.getcwd)




main()

