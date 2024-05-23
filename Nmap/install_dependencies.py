#!/usr/bin/env python3
import os
import sys

sys_vers = sys.platform()
if sys_vers == 'linux':
    os.system("cat /etc/os-release")

    if os.system('"$ID" == "debian"') or os.system('"$ID" == "ubuntu"') or os.system('"$ID" == "kali"'):
        os.system(
                "apt update; apt upgrade; apt install nmap; sudo apt install python3-pip; pip install python-nmap; apt-get install python3"
        )

    elif os.system('"$ID" == "rhel"') or os.system('"$ID" == "centos"') or os.system('"$ID" == "fedora"'):
            os.system(
            "dnf update; yum upgrade; sudo dnf install python3-pip; pip install python-nmap; dnf install python"
            )
else:
    print("This script is running on an unsupported distribution.")
