#!/usr/bin/env python3
import os


if sys_vers == 'linux':
    os.system("source /etc/os-release")

    if os.system('"$ID" == "debian"'):
        os.system(
                "apt update; apt upgrade; apt install nmap; sudo apt install python3-pip; pip install python-nmap; apt-get install python3"
        )

    elif os.system('"$ID" == "rhel"') or os.system('"$ID" == "centos"') or os.system('"$ID" == "fedora"'):
            os.system(
            "dnf update; yum upgrade; sudo dnf install python3-pip; pip install python-nmap; dnf install python"
            )
elif sys_vers == 'win32':
    # i need to update the system, download nmap, and make sure python, pip, and the nmap module are all installed. 
    pass

else:
    print("This script is running on an unsupported distribution.")
