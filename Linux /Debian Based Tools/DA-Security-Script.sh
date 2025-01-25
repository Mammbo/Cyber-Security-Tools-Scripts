#!/bin/bash

#variables for users and program prompts

function get_users {
    # The <65534 condition is to skip the nobody user and get all user accounts
    users=$(awk -F: '{if ($3 >= 1000 && $3 < 65534) print $1}' < /etc/passwd)
}

# prompt and reprompt_var functions from https://gitlab.com/-/snippets/2434448

#sets up the prompt for us to input our data/ files/ locations

function prompt {
    if [ "$2" = 'y' ]; then
   	 prompt_text="$1 [Y/n]: "
    elif [ "$2" = 'n' ]; then
   	 prompt_text="$1 [y/N]: "
    else
   	 prompt_text="$1 [y/n]: "
    fi

    while true; do
   	 read -r -p "$prompt_text" input

   	 case "$input" in
   		 [yY][eE][sS]|[yY])
       		 return 1
       		 ;;
   		 [nN][oO]|[nN])
       		 return 0
       		 ;;
   		 "")
       		 if [ "$2" = "y" ]; then return 1
       		 elif [ "$2" = "n" ]; then return 0
       		 else echo "Invalid response"
       		 fi
       		 ;;
   		 *)
       		 echo "Invalid response"
       		 ;;
   	 esac
    done
}

function reprompt_var {
    local reprompt_text="$1"
    local reprompt_new_val=''
    reprompt_value="${!2}"

    if [ $reprompt_value ]; then reprompt_text+=" [$reprompt_value]: "
    else reprompt_text+=': '; fi

    read -r -p "$reprompt_text" reprompt_new_val

    if [ "$reprompt_new_val" ]; then reprompt_value="$reprompt_new_val"; fi
}





echo
echo
echo
echo
echo ' ______   	 __                      		 '
echo '  / ____/__  __ / /_   ___   _____          		 '
echo ' / /    / / / // __ \ / _ \ / ___/          		 '
echo '/   /___ / /_/ // /_/ //  __// /              		 '
echo '\____/ \__, //_.___/ \___//_/               		 '
echo ' 	 /____/                                		 '
echo ' _____                               		 _   '
echo '/ ___/ ____ _ ____ ___   __  __ _____ ____ _ (_) '  
echo ' \__ \ / __ `// __ `__ \ / / / // ___// __ `// / '   
echo '___/ // /_/ // / / / / // /_/ // /   / /_/ // / '    
echo '/____/ \__,_//_/ /_/ /_/ \__,_//_/    \__,_//_/ '   
echo
echo
echo
echo  
                                           		 
# checks to see if the script is executed with root privellages

user=$(whoami)

if [ "$user" != 'root' ]; then
	echo 'Run this in root!'
	echo "Current user: $user"
	exit 1
fi



#log files


#variables for the automatic updates files
apt_periodic_conf='/etc/apt/apt.conf.d/10periodic'
apt_autoupgrade_conf='/etc/apt/apt.conf.d/20auto-upgrades'

#important groups
admin_groups='sudo adm lpadmin sambashare'

#important Configuration Files
user_conf='/etc/lightdm/user.conf'
sshd_conf='/etc/ssh/sshd_config'
samba_conf='/etc/samba/smb.conf'
ftp_config='/etc/vsftpd.conf'
kernel_params='/etc/sysctl.conf'


#Passwords for services
sambapass="7VP9nGc>N/.)MCaf3W"
ftppass='90i%G&$2KuB`0m*eiZc%'

#variables for FTP service
ftpuser='ftpuser'
shells='/etc/shells'
ftponlyfile='/bin/ftponly'

#List all media files
media_files_raw=(

    # Audio formats
    'mp3'
    'mpc'
    'msv'
    'nmf'
    'ogg'
    'oga'
    'mogg'
    'opus'
    'ra'
    'raw'

    # Video formats
    
    'gif'
    'gifv'
    'mng'
    'rm'
    'amv'
    'mp4'
    'm4p'
    'mp2'
    'mpeg'
    'mpv'
    'mov'
    'wmv'
    'm2v'

    # Picture formats
    'png'
    'jpg'
    'jpeg'
    'jfif'
    'tif'
    'tiff'
    'gif'
    
    # user directories
    'txt'
    'xls'
    'exe'
    'xlsx'
    'doc'
    'docx'
    'zip'
    '7z'
    'tar'
    'tgz'
    'bz2'

 
)

found_media_file='media.log'
media_path='/home/'

media_files=()

# Convert list of extensions to parameters for find command
for extension in "${media_files_raw[@]}"; do
    if [ $media_files ]; then media_files+=('-o'); fi
    media_files+=('-iname')
    media_files+=("*.$extension")
done



#clamscan variables
clamscan_path='/'
clamscan_logs='clamav.log'
found_media_file='media.log'
clamscan_params=()



#Delete the bad stuff (aka hacking tools)

bad_software=("wireshark-qt" "nmap" "medusa" "john" "sqlmap" "hydra" "zenmap" "ophcrack" "tcpdump" "kismet" "snort" "fwsnort" "nessus" "netcat-traditional" "aircrack-ng" "nikto" "wifite" "yersinia" "hashcat" "macchanger" "pixiewps" "bbqsql" "proxychains" "whatweb" "dirb" "traceroute" "httrack" "openvas" "4g8" "acccheck" "airgraph-ng" "bittorrent" "bittornado" "bluemon" "btscanner" "buildtorrent" "brutespray" "dsniff" "ettercap" "hunt" "nast" "netsniff-ng" "python-scapy" "sipgrep" "sniffit" "tcpick" "tcpreplay" "tcpslice" "tcptrace" "tcptraceroute" "tcpxtract" "irpas" "mdk3" "reaver" "slowhttptest" "ssldump" "sslstrip" "thc-ipv6" "bro" "darkstat" "dnstop" "flowscan" "nfstrace" "nstreams" "ntopng" "ostinato" "softflowd" "tshark" "gameconqueror" "manaplus" "socat" "fcrackzip" "dsniff" "rfdump" "bind9" "deluge-gtk" "ettercap-common" "telnet" "free-civ" "endless-sky" "rsh-server" "telnetd" "pvgn" "sucrack" "changme" "unworkable")



function menu {

	echo ' 1)  Run Updates                       		 31)  List all media Files '   
	echo ' 2)  Enable Automatic Updates          		 32) Run Auditing Tool Lynis'
	echo ' 3)  Set Up UFW                        		 33) Configure AppArmor'
	echo ' 4)  Delete Unauthorized Users         		 34) Edit Hosts file '
	echo ' 5)  Add Missing Users                 		 35) Edit Nameservers File'
	echo ' 6)  Fix Administrators                		 36) Edit Repositories '
	echo ' 7)  Change All Passwords              		 37) Check Installed Packages'
	echo ' 8)  Create a Group and Add Users to it		 38) Edit Sudoers File'
	echo ' 9)  Lock or Change Root password/account 	39) Check for illegitmate services'
	echo ' 10) Disable Guest Account             		 40) Password Aging Policies'
	echo ' 11) Configure SSH    			 41) Password Authentication and strong passwords'   	 
	echo ' 12) Configure Samba  			 42) Systemctl Configurations'
	echo ' 13) Configure FTP   			 43) Etc sys configs(PAM,auditing,hosts,DCCP,ntp,motd,coredump,ip spoof'    
	echo ' 14) Configure PostFix         44) View Shared Memory'
	echo ' 15) Configure Nginx           45) View Immutable Files/Dirs'
	echo ' 16) Configure Apache          46) Find all SUID/SGID Bits'
	echo ' 17) Configure NFS      		 47) Find all Sticky Bits'
	echo ' 18) Configure Kernel			 48) Htop Process Viewer'
	echo ' 19) Secure and edit Cron		 49) List Masked Services'
	echo ' 20) Add Your Own Scripts to Cron 				50) Debsums'
	echo ' 21) Configure DNS( Domain Name Server ) 			51) View Kernel Modules'
	echo ' 22) Configure NTP ( Network Transfer Protocol ) 	52) Check for Blank Passwords'
	echo ' 23) List files with high file Permissions 		53) Check for nullok in common-password'
	echo ' 24) Delete Unauthorized Software					54) Change Directory Permissions'
	echo ' 25) Check Perms for Important Files				55) Directories to maybe add a Sticky Bit'
	echo ' 26) Clear /etc/rc.local							56) Configure to Use pam_faillock'
	echo ' 27) List all Running Services					57) Password Configuration and security'
	echo ' 28) Run RKHunter									58) Check if multiple users have the same UID'
	echo ' 29) Run ClamAV'
	echo ' 30) Run Chkroot'
	echo
	echo '99) Exit Script'
	read -r -p '> ' input

	case $((input)) in


	#Run Updates

	1)
  	  sudo apt-get update
  	  sudo apt-get upgrade -y
  	  sudo apt-get dist-upgrade

  	  echo -e “System has been updated!”
  		  ;;
  		 
  		 
	# Enable automatic updates

	2)

    #!/bin/bash

# Enable automatic updates in 10periodic file

# Set how often APT checks for updates (in days)
sudo sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/' /etc/apt/apt.conf.d/10periodic

# Set how often APT downloads available package updates (in days)
sudo sed -i 's/APT::Periodic::Download-Upgradeable-Packages "0";/APT::Periodic::Download-Upgradeable-Packages "1";/' /etc/apt/apt.conf.d/10periodic

# Set how often APT installs security updates automatically (in days)
sudo sed -i 's/APT::Periodic::Unattended-Upgrade "0";/APT::Periodic::Unattended-Upgrade "1";/' /etc/apt/apt.conf.d/10periodic

# Set the interval for cleaning package cache (in days)
sudo sed -i 's/APT::Periodic::AutocleanInterval "0";/APT::Periodic::AutocleanInterval "7";/' /etc/apt/apt.conf.d/10periodic

# Run apt update to refresh the package lists
sudo apt update

# Upgrade installed packages (with -y to automatically confirm)
sudo apt upgrade -y

sudo dpkg-reconfigure unattended-upgrades


  	  #installs unattended upgrades
  	  sudo apt-get install unattended-upgrades

  	  #changes the configuration files for automatic updates

   #     cat "/etc/apt/apt.conf.d/10periodic" "/etc/apt/apt.conf.d/20auto-upgrades" 2>/dev/null | sed "s/0/1/" | sed "s/\(APT::Periodic::AutocleanInterval\s*\"\).*\";/\17\";/" | sort -u | sudo tee "/	etc/apt/apt.conf.d/21periodic-auto-upgrades_on"



  	#	sed  “s/APT::Periodic::AutocleanIntervals

  	  #copies the changes to the other folder
  	  cp -f "$apt_periodic_conf" "$apt_autoupgrade_conf"
      
  	  #enable the service

  	  sudo systemctl enable unattended-upgrades

  	  # run the upgrade

  	  sudo unattended-upgrades -v
  		  echo ' Automatic Updates have been enabled :3 '
  		  ;;

#check after script with this to see the changes, if not then just click them off the changes are internally
#Software Updates,
#Settings > system settings > Software and Updates >
# Check off Important Security Updates
#Recommended Updates,
# Automatically Check for Updates Daily
# When there are security updates Download and install Automatically





	# set up UFW

	3)
  	  #installs ufw

  	  sudo apt-get install ufw -y

  	  echo -e "UFW has been installed!"

  	  #resets whatever firewall may be there
  	  sudo iptables -F

  	  sudo ufw reset

  	  echo -e "UFW has been reseted!"

  	  #enable firewall

  	  sudo ufw enable

  	  echo -e "UFW has been enabled!"

  	  #turns on the logs to high to mark all incoming traffic

  	  sudo ufw logging on high

  	  echo -e "UFW logging is now on high!"

  	  #directions of traffic coming into the server

  	  sudo ufw default allow outgoing
  	  sudo ufw default deny incoming

  	  echo -e "UFW traffic has been configured!"

  	  #allows remote access to computer

  	  sudo ufw allow OpenSSH

  	  echo -e "UFW has allowed SSH!"

  	  #allows only this port for remote access (security)

  	  sudo ufw allow 50638

  	  echo -e "UFW has allowed the new SSH port!"

  	  #denys ports and stuffs

  	  sudo ufw deny 21
  	  sudo ufw deny 22
  	  sudo ufw deny 23
     sudo ufw deny 5800
     sudo ufw deny 5801
     sudo ufw deny 5901
         	sudo ufw deny 5900
  	  sudo ufw deny cups

  	  echo -e "UFW has denyed ports and services!"

  	  #uninstall services that could be targeted

  	  sudo apt-get purge -y cups
  	  sudo apt-get purge -y bluetooth

  	  echo -e "Services that could be targeted are now deleted!"

  	  # configure default deny

  	  sudo iptables -P INPUT DROP
  	  sudo iptables -P OUTPUT ACCEPT
  	  sudo iptables -P FORWARD DROP

  	  echo -e "Default deny has now been configured!"
 

  	  # loopback traffic
    
  	  sudo iptables -A INPUT -i lo -j ACCEPT
  	  sudo iptables -A OUTPUT -o lo -j ACCEPT

  	  echo -e "Loopback Traffic is now working!"

  	  #outbound and established connections

  	  sudo iptables -A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT
  	  sudo iptables -A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT
  	  sudo iptables -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT
  	  sudo iptables -A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT
  	  sudo iptables -A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT
  	  sudo iptables -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT

  	  echo -e "Outbound and Established Connections have now been configured!"

  	  echo -e "The UFW fire wall has now been configured and set up :3!"
  		  ;;
  		 
  		 
  		 
#everything user tbh

#Make list of authorized users/ admins / standard users
#sudo mkdir -p /etc/customconfigs/
#sudo nano /etc/customconfigs/allowed_users.txt

#copy paste list of users from cyberpatriot list of well users (duh)
#Ctrl O, Ctrl X
#sudo chmod 600 /etc/customconfigs/allowed_users.txt

#sudo nano /etc/customconfigs/admin_file.txt
#copy and paste list of users from cyber patriot list of admins
#Ctrl O, Ctrl X
#Sudo chmod 600 /etc/customconfigs/admin_file.txt

#sudo nano /etc/customconfigs/normal_user_file.txt
#copy and past list of users from cyber patriot list of normal users
#Ctrl O,Ctrl X
#sudo chmod 600 /etc/customconfigs/normal_user_file.txt
#After it has been completed : sudo chattr -R +i /etc/customconfigs/
#( to make mutable change -R +i > -i
# deleting unauthorized users


	# Delete Unauthorized Users
    
    
	4)

  	reprompt_var 'Path to list of allowed usernames (normal users and admins)' users_file
  		      users_file="$reprompt_value"
  		      get_users

  		      unauthorized=()

  		      for user in $users; do
  		 		 if ! grep -Fxq "$user" "$users_file"; then
  		     		 echo Unauthorized user: $user
  		     		 unauthorized+=("$user")
  		 		 fi
  		      done
    
  		      if [ $unauthorized ]; then
  		 		 prompt 'Delete found users?'

  		 		 if [ $? = 1 ]; then
  		     		 for user in "${unauthorized[@]}"; do
  		         		 echo Deleting $user
  		         		 userdel $user
  		     		 done
  		 		 fi
  		      fi

  		      echo 'Done!'
  		      ;;
  			 
  			 

	#add missing users
	#uses same authorized user file to find the missing users

	5)

	reprompt_var 'Path to list of allowed usernames (normal users and admins)' users_file
  		      users_file="$reprompt_value"
  		      get_users

  		      while IFS= read -r user || [ -n "$user" ]; do
  		 		 if ! [ "$user" ]; then continue; fi
  		 		 if ! printf "$users" | grep -wq "$user"; then
  		     		 echo Adding missing user $user
  		     		 useradd $user
  		 		 fi
  		      done < "$users_file"

  		      echo 'Added missing users!'
   	      ;;
   	 
   	 
   	 
	#Fix Administrators
	6)

	reprompt_var 'Path to list of administrators' admin_file
       		 admin_file="$reprompt_value"
       		 reprompt_var 'Path to list of normal users' normal_file
       		 normal_file="$reprompt_value"
       		 # reprompt_var 'Add/remove users to all administrative groups?' sudo_group
       		 # sudo_group="$reprompt_value"
       		 get_users

       		 echo 'Ensuring admins are part of the admin group'

       		 while IFS= read -r admin || [ -n "$admin" ]; do
           		 if ! [ "$admin" ]; then continue; fi
    
           		 for group in $admin_groups; do
               		 if ! id -nG "$admin" | grep -qw "$group"; then
                   		 echo "User $admin isn't in group $group, fixing"
                   		 gpasswd --add "$admin" "$group"
               		 fi
           		 done
       		 done < "$admin_file"
    
       		 echo 'Ensuring standard users are not part of the sudo group'
    
       		 while IFS= read -r normal || [ -n "$normal" ]; do
           		 if ! [ "$normal" ]; then continue; fi
    
           		 for group in $admin_groups; do
               		 if id -nG "$normal" | grep -qw "$group"; then
                   		 echo "User $normal is in group $group and shouldn't be, fixing"
                   		 gpasswd --delete "$normal" "$group"
               		 fi
           		 done
       		 done < "$normal_file"

       		 echo 'Done fixing administrators!'
           		 ;;
  		 
  		 
  		 
	# change all passwords
	7)
    
    
    	reprompt_var 'Path to list of users' admin_file
	admin_file="$reprompt_value"
 
	selected_admins=$(cat "$admin_file")
    
		  echo 'Changing passwords for the following users:'
   	  echo $selected_admins
    
    
	selected_admins=$(cat "$admin_file")
 
 
	while true; do
    
  	  PS3="Select an administrator to change password for: "
     	select admin_user in $selected_admins; do
    
     		  if [[ -n "$admin_user" ]]; then
				  new_pass=''
				  new_pass_confirm=''

		 
			   	while ! [ "$new_pass" = "$new_pass_confirm" ] || [ "$new_pass" = '' ]; do
				  	  read -s -p 'New password: ' new_pass
				  	  echo
				  	  read -s -p 'Confirm: ' new_pass_confirm
				  	  echo

     				  if ! [ "$new_pass" = "$new_pass_confirm" ]; then
				   	echo 'Passwords do not match!'
				 
     				  else
						  echo "Changing for $user..."
   					  printf "$admin_user:$new_pass" | chpasswd
				 
					  fi
     		  	 done
          		  break
     		  fi
   		  done

    
    
 	 
  	  prompt 'Ya wanna stop now ????'
     	   if [ $? -eq 1 ]; then
     	   break
			  	 
     	   fi
	done

		 
		 
	echo 'Done changing passwords!'
   	 ;;


	#create a group and add users to it.
	8)
    
    
    

	#enter list of authorized users to then create a drop down menu
	reprompt_var "Path to list of authorized users" allowed_users
	allowed_users="$reprompt_value"

	#prints the list of users out
	selected_users=$(cat "$allowed_users")
 
  			echo 'Adding the the following users:'
  			echo $selected_users
    
    
	selected_users=$(cat "$allowed_users")

	#uses group name entered to create the group
	reprompt_var "What is the name of the group you want to add?" group_name
	group_name="$reprompt_value"


	sudo groupadd "$group_name"


	#Creates a drop down menu to select users
	while true; do

  		PS3="Select a user to add to a group: "
		 select user in $selected_users; do
    
		 #lets you type in the user again(assigns the users to a variable
    		 reprompt_var "What is the name of the user?" user
 		   user="$reprompt_value"
	#uses both group variable and user variable to assign user to the group
 		   if [[ -n "$selected_users" ]]; then
 			   sudo usermod -a -G "$group_name" "$user"
     	 
 		   break    
 		   fi
		 done
   	 #let's you add another user or break the cycle
		 prompt 'Ya wanna stop now ????'
			if [ $? -eq 1 ]; then
			 
   		  break     
  		 fi    
 	done
    

 	 
	echo "Group has been added and users have been added :3"
   	 ;;
  	 
  	 
  	 

	#lock root account
	9)
    
    
    
   	  prompt 'Do you want to lock or change root account password ?'
   	  if [ $? = 1 ]; then
   	 
   	      
         read -r -p 'Account to lock [root]: ' lock_account

  		  if [ "$lock_account" = '' ]; then lock_account='root'; fi

  		  usermod -dL $lock_account
  		  echo "Locked $lock_account!"
  		      
  	 else
  		      
		 sudo passwd root
  		 echo "root password has been changed"
  	 fi
  	      ;;
  		 
    
 		 
	#disable guest account
	10)

	if [[  -f "$user_conf" ]]; then

   	 if grep -q 'allow-guest=false' "$user_conf"; then
 		   echo "The Guest account is already disabled"
    
   	 else
 		   sed -i "s/allow-guest=true/allow-guest=false/" "$user_conf"
 		   echo "allow-guest=false" >> "$user_conf"
      
 		   echo 'Lightdm has been configured! (Guest account has been disabled! :3'
 		   sudo restart lightdm
   	 fi
    
	else
  	  echo "lightdm config file not found at $user_conf, guest account probably does not exist idk figure it out lol"
 	 
	fi
   	 ;;
  	 
  	 
   	 #Configure services
  	 
   	 11)
  	  ##SSH##

  	  #variables for /the user you are on/ and the sshd_config file

  	  reprompt_var "name of the user you are on"
  	  username="$reprompt_value"

  	  #prompts the users to configure ssh
  	  prompt 'Do you want to configure and secure SSH' 'y'
  	  if [ $? = 1 ]; then

  	  #installs ssh
  	  sudo apt-get install ssh -y

  	  mkdir ~/.ssh && chmod 700 ~/.ssh
  	  #create a directory for authorized keys and creates a key, copies the key and 	then changes permissions on the sshd config file

  	  sudo touch ~/.ssh/authorized_keys
  	  ssh-keygen -b 4096

  	  ssh-copy-id -i ~/.ssh/id_rsa.pub

  	  fi

  	  prompt 'Do you want to put configurations into sshd_conf?'
  	  if [ $? = 1 ]; then

  	  #configure permissions in the configuration file
  	  sed  -i "s/PermitRootlogin/PermitRootLogin no/" $sshd_conf
  	  echo "PermitRootLogin no" >> $sshd_conf
  	  echo "AllowUsers" $username >> $sshd_conf
  	  echo "Port 50638" >> $sshd_conf
  	  echo "LoginGraceTime 2m" >> $sshd_conf
  	  echo "StrictModes yes" >> $sshd_conf
  	  echo "MaxAuthTries 6" >> $sshd_conf
  	  echo "HostbasedAuthentication no" >> $sshd_conf
  	  echo "IgnoreRhosts yes" >> $sshd_conf
  	  echo "PasswordAuthentication yes" >> $sshd_conf
  	  echo "X11Forwarding=no" >> $sshd_conf
  	  echo "UsePAM yes" >> $sshd_conf
  	  echo "Protocol 2" >> $sshd_conf


  	  fi

  	  prompt 'Do you want to restart and set up ssh ?'
  	  if [ $? = 1 ]; then
    
  	  sudo systemctl restart sshd
  		  ufw allow ssh
  		  systemctl enable ssh
  		  systemctl restart ssh
  	  sudo ufw allow 50638

  	  echo "Done configuring SSH :)"

  	  else

  	  echo 'Stopping service'
				  systemctl stop ssh
  	 		 systemctl disable ssh
  	  echo 'Uninstalling'
  		   sudo apt-get purge openssh-server -y
  	  echo 'Configuring UFW rules'
  		   ufw delete allow ssh
  	  echo 'ssh disabled and purged!'
  	  fi
     ;;


  	  ###SAMBA###
     12)

  	  reprompt_var "name of the user you are on"
  	  username="$reprompt_value"

  	  #prompts the users to configure ssh
  	  prompt 'Do you want to configure and secure Samba ?' 'y'
  	  if [ $? = 1 ]; then

  	  #installs samba
  	  sudo apt-get install samba -y
    
  	  mkdir /home/$username/sambashare/


  	  fi
      
    
    
    
  	  prompt 'Do you want to put configurations into smb_conf?'
  	  if [ $? = 1 ]; then

  	  #configure permissions in the configuration file

  	      echo "min protocol = SMB2" >> $samba_conf
  	      echo "map to guest = never" >> $samba_conf
  	      echo "restrict anonymous = 2" >> $samba_conf
  	      echo "hosts allow = 127.0.0.1 192.168.1.0/24" >> $samba_conf
  	      echo "hosts deny = 0.0.0.0/0" >> $samba_conf
  	      echo "usershare allows guests = no" >> $samba_conf
    
  	      echo "[sambashare]" >> $samba_conf
  	      echo "comment = Samba on Ubuntu" >> $samba_conf
  	      echo "path = /home/$username/sambashare" >> $samba_conf
  	      echo "read only = no" >> $samba_conf
  	      echo "browsable = yes" >> $samba_conf

  	  fi

  	  prompt 'do you want to restart and set up samba ?'
  	  if [ $? = 1 ]; then

  	      sudo service smbd restart
  	   		   ufw allow samba
  	   		   systemctl enable smbd
      
  	  # kool flag that uses the pass variable to pipe inot the smbpasswd command and also puts the username we inputed all the way at the top into this script
  	      echo -e "$sambapass\n$sambapass" | smbpasswd -a -s $username


  	      echo "Done configuring Samba :)"

  	  else
  	   	echo 'Stopping service'
  		  		  systemctl stop smbd
  		  		  systemctl disable smbd
  	   	echo 'Uninstalling'
  		  		  apt-get purge samba -y
  	   	echo 'Configuring UFW rules'
  		  		  ufw delete allow samba
  	   	echo 'Samba disabled and purged!'
  	  fi
     ;;



  	  ##FTP##
     13)
    
    
  	  prompt 'Allow FTP (with VSFTPD) on machine ?'

  	  if [ $? = 1 ]; then

  	  #installs vsftpd
  		  sudo apt-get install vsftpd -y
  		  echo 'copying crtical config file'
  		  sudo cp /etc/vsftpd.conf /etc/vsftpd.conf.orig
    
  		  echo 'Configuring UFW rules'
  		  sudo ufw allow ftp
  		  sudo ufw allow 20,21,990/tcp
  		  sudo ufw allow 40000:50000/tcp
    
  	  prompt 'Do you want to create a ftp user ?' 'y'
  	  if [ $? = 1 ]; then

    
  	      useradd -m -p $ftppass $ftpuser
  	      #creates directory for ftp services and ftp user
  	      sudo mkdir /home/$ftpuser/ftp
  	      #changes perms for dir
  	      sudo chmod a-w /home/$ftpuser/ftp
  	      #make files folder for ftp
  	      sudo mkdir /home/$ftpuser/ftp/files
    
    
  	      #change dir perms
  	      sudo chown ftpuser:ftpuser /home/$ftpuser/ftp/files
  	      sudo chown nobody:nogroup /home/$ftpuser/ftp
  	  fi

  	  prompt 'Do you want to configure FTP Access?' 'y'
  	  if [ $? = 1 ]; then

  	      #configuring files and taking off comments using sed
  	      sed -i "s/anonymous_enable/anonymous_enable=NO/"  $ftp_config
  	      sed -i "s/anonymous_enable/anonymous_enable=NO/"  $ftp_config
  	      sed -i "/^annoymous_enable/ c\chroot_local_user=YES" $ftp_config
  	      sed -i "/^anon_upload_enable/ c\anon_upload_enable no" $ftp_config
  	      sed -i "s/local_enable/local_enable=YES/"  $ftp_config
  	      sed -i "s/local_enable=NO/local_enable=YES/"  $ftp_config
  	      #takes off comments from lines
  	      sed -i '/write_enable=YES/s/^#//' $ftp_config
  	      sed -i '/^chroot_local_user/ c\chroot_local_user=YES' $ftp_config
  	      sed -i '/chroot_local_user=YES/s/^#//' $ftp_config
  	      #add lines for users to be directed to the appropitate user's home directory
  	      echo "user_sub_token=ftpuser" >> $ftp_config
  	      echo "local_root=/home/ftpuser/ftp" >> $ftp_config
  	      #limit the range of ports that passive ftp can use
  	      echo "pasv_min_port=40000" >> $ftp_config
  	      echo "pasv_max_port=50000" >> $ftp_config
  	      #allowing FTP access on a case-by-case basis
  	      echo "userlist_enable=YES" >> $ftp_config
  	      echo "userlist_file=/etc/vsftpd.userlist" >> $ftp_config
  	  fi

  	  prompt 'Do you want to add your ftpuser to the /etc/vsftpd.userlist ?' 'y'
  	  if [ $? = 1 ]; then
    
  	      #adds user to the /etc/vsftpd.userlist
  	      echo "ftpuser" | sudo tee -a /etc/vsftpd.userlist
  	      #resarts ftp
  	      sudo systemctl restart vsftpd
  	  fi

  	  prompt 'Do you want to encrypt ftp transactions with ssl/tls ?' 'y'
  	  if [ $? = 1 ]; then
    
  	      #creates a rsa public key and creates secure transactions
  	      sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem
  	      #puts comments on these config lines  
  	      sed -i '\|etc/ssl/certs/ssl-cert-snakeoil.pem|s/^/#/g' $ftp_config
  	      sed -i '\|etc/ssl/private/ssl-cert-snakeoil.key|s/^/#/g' $ftp_config

    
  	  fi
    
  	  prompt 'Do you want to continue with encryption?' 'y'
  	  if [ $? = 1 ]; then

  	      #config that points to key
  	      echo "rsa_cert_file=/etc/ssl/private/vsftpd.pem" >> $ftp_config
  	      echo "rsa_private_key_file=/etc/ssl/private/vsftpd.pem" >> $ftp_config
  	      #force ssl
  	      echo "ssl_enable=YES" >> $ftp_config
  	      #deny anonymous connections over SSL
  	      echo "allow_anon_ssl=NO" >> $ftp_config
  	      echo "force_local_data_ssl=YES" >> $ftp_config
       		 echo "force_local_logins_ssl=YES" >> $ftp_config
       		 #configure the server to use TLS (successor to ssl)
       		 echo "ssl_tlsv1=YES" >> $ftp_config
       		 echo "ssl_sslv2=NO" >> $ftp_config
       		 echo "ssl_sslv3=NO" >> $ftp_config
       		 #add two final options(not require ssl reuse and require "high" encryption cipher suites)
       		 echo "require_ssl_reuse=NO" >> $ftp_config
       		 echo "ssl_ciphers=HIGH" >> $ftp_config
  	  fi

  	  prompt 'Do you want to Disable Shell Access (Optional)' 'y'
  	  if [ $? = 1 ]; then
    
     		echo "#!/bin/sh" >> $ftponlyfile
     		echo "echo 'This account is limited to FTP access only.'" >> $ftponlyfile
     		#change perms of the dir
     		sudo chmod a+x /bin/ftponly
     		#configure shells
     		echo "$ftponlyfile" >> $shells
     		#usermod our ftp user to change ssh perms
     		sudo usermod ftpuser -s /bin/ftponly
	 
     	  #starts up ftp
  		  systemctl enable vsftpd
  		  systemctl restart vsftpd
    
  		  echo "FTP has now been configured :)"
  		  echo "Remember to test the FTP server manually using the section of the checklist designed for it :)"
  	  fi
  	  else
     	   echo 'Stopping service'
  		  systemctl stop vsftpd
  		  systemctl disable vsftpd
  		  echo 'Uninstalling'
  		  sudo apt-get purge ftpd vsftpd -y
  		  sudo systemctl stop pure-ftpd
  		  echo 'Configuring UFW rules'
  		  ufw delete allow ftp
  		  echo 'FTP disabled and Purged wooooooooo'
  	  fi    
     ;;


  	  ##PostFix##
     14)
    
    
   	  prompt 'Allow Mail (with Postfix) on machine?'

   	   		  if [ $? = 1 ]; then
      				  apt-get install postfix -y

      			  echo 'Configuring UFW rules'
      				  ufw allow smtp

      				  systemctl enable postfix
      				  systemctl restart postfix
      			  echo 'Done configuring Postfix!'

   	   		  else
      				  echo 'Stopping service'
      				  systemctl stop postfix
      				  systemctl disable postfix
      			  echo 'Uninstalling'
      				  apt-get purge postfix -y
      			  echo 'Configuring UFW rules'
      				  ufw delete allow smtp
      			  echo 'Postfix disabled and purged!'
   	   		  fi
   			  ;;


    #Nginx    
    15)
   	 


   	 
   	 prompt 'Allow Nginx web server on machine ?' 'n'
   	 if [ $? = 1 ]; then

   		 echo 'Installing Nginx...'
   		 sudo apt update
   		 sudo apt install nginx
   		 #set up firewall     
   		 sudo ufw allow ‘Nginx HTTPS’
   		 #check if it is running
   		 systemctl status nginx
   		 #get your IP
   		 curl -4 icanhazip.com

   		 echo 'Your Nginx web server is now up, check in your browser ur with https://your-server_ip to visit your website!'
    
   		 

   	 else
   		  echo 'Stopping service'
      				  systemctl stop nginx
      				  systemctl disable nginx
      			  echo 'Uninstalling'
      				  apt-get purge nginx -y
      			  echo 'Configuring UFW rules'
      				  ufw delete allow nginx
      			  echo 'Nginx disabled and purged!'
   	 fi
   	 ;;
    






   	 #Apache
   	 16)
    
   		 prompt  'Do you want to install and configure or disable Apache ?' 'n'
   		 if [ $? = 1 ]; then
  	 
  			  #housekeeping before downloading apache
  			  apt update
   		  apt dist-upgrade
  	 
  	     	 #set up hostname for the server
  	     	 cp /etc/hostname /etc/hostname.orig
  	     	 true > /etc/hostname

  	     	 reprompt_var 'What do you want to name the server ?'
  	     	 servername="$reprompt_value"
  	 
  	     	 echo "$servername" >> /etc/hostname

  	     	 # edit the /etc/hosts to add server name
  	     	 sed -i "2i 127.0.1.1   	 $servername" /etc/hosts

  	     	 #install apache
  	     	 apt install apache2
  	     	 apt install apache2-doc
  	     	 apt install apache2-utils
  	     	 systemctl enable apache2
  	 
  	     	 #install any modules for apache
  	     	 prompt 'Do you want to install modules for Apache ?'
  	     	 if [ $? = 1 ]; then

  				  while true; do
  		 
  					  #list all modules
  					  apt search libapache2-mod
  			 

  					  reprompt_var 'Which modules do you want to download? (format) libapache2-mod-<module name> '
  					  mod="$reprompt_value"
  			 
  					  sudo apt install $mod
  					  a2enmod
  					  systemctl restart apache2
    
  					  prompt 'Do you want to disable a module ?'
						  if [ $? -eq 1 ]; then

  						  a2dismod
  						  systemctl restart apache2

  					  else
  				 		  break
  					 
						  fi
  				  done
  		 
  	     	 fi    
  	 
  				  prompt 'Do you want to configure sites ?'
  				  if [ $? -eq 1 ]; then
  		 
  					  prompt 'Do you want to enable or disable sites on your apache server?'
  					  if [ $? -eq 1 ]; then  					 
  			 
  						  ls /etc/apache2/sites-available
  		 
  						  reprompt_var 'what site do you want to enable?'
  						  site_enable="$reprompt_value"
  			 
  						  a2ensite $site_enable
  						  systemctl reload apache2
  						  echo 'Sites have been enabled!'
  					  else    
  						  ls /etc/apache2/sites-available
  		 
  						  reprompt_var "what site do you want to disable?"
  						  site_disable="$reprompt_value"
  				 
  						  a2dissite $site_disable
  						  systemctl reload apache2  					 
  						  echo 'Sites have been disabled'
  			 
  					  fi

    
  				  else
  					  prompt 'Do you want to set up a custom site ? '
  					  if [ $? -eq 1 ]; then
  			 
  						  #sets up custom site
  						  reprompt_var 'What is the name of the website conf file (example.net.conf)?'
  						  web_name="$reprompt_value"
  				 
  						  touch /etc/apache2/sites-available/$web_name
  				 
  						  #gathers configs for the website configuration
  				 
  						  reprompt_var 'what port is your system listening on?'    
  						  port="$reprompt_value"
  				 
  						  reprompt_var 'What email is the web server using?'
  						  email="$reprompt_value"
  			 
  						  reprompt_var 'What is the servername (example.net)?'
  						  servername="$reprompt_value"

  						  reprompt_var 'what is the server name in www format?'
  						  webformat="$reprompt_value"
  		 
  						  echo "<VirtualHost *:$port>" >> /etc/apache2/sites-available/$web_name
  						  echo "  	  ServerAdmin $email" >> /etc/apache2/sites-available/$web_name
  						  echo "   	  ServerName $servername" >> /etc/apache2/sites-available/$web_name
  						  echo "   	  ServerAlias $webformat" >> /etc/apache2/sites-available/$web_name
  						  echo "   	  DocumentRoot /srv/www/$servername/public_html/" >> /etc/apache2/sites-available/$web_name
  						  echo "  	  ErrorLog /srv/www/$servername/logs/error.log" >> /etc/apache2/sites-available/$web_name
  						  echo "  	  CustomLog /srv/www/$servername/logs/access.log combined" >> /etc/apache2/sites-available/$web_name
  						  echo "</VirtualHost>" >> /etc/apache2/sites-available/$web_name

  						  #creates directories in the virtual host config file
  						  mkdir -p /srv/www/$servername/public_html
  						  mkdir -p /srv/www/$servername/logs
  						  #enable the site an firewall config
  						  ufw allow $port
  						  a2ensite $servername
  						  systemctl reload apache2
  					 
  						  echo "Duly noted! You are now done, there is a lot more make sure to go more in depth in your configs, as well as to host another website run this script again "

  					  else
  				 
  						  echo "Duly noted! You are now done, there is a lot more make sure to go more in depth in your configs, as well as to host another website run this script again "
  	 
  	 
  					  fi
  			 
  			 

   		 fi

  	 
     	   else
    
     	       systemctl stop apache2
   		  systemctl disable apache2
     	   	  apt-get purge apache2 -y
     	   	  ufw delete allow apache2
     	 	echo "Disabled!"

     	   fi
   	   ;;
    







   	 # NFS service
   	 17)
   	 
   	 
    
   		 # Gather IP address
   		 ip=$(hostname -I)

   		 prompt 'Do you want to configure or disable NFS ?' 'y'
   		 if [ $? = 1 ]; then
   		 	prompt 'Do you want to configure an NFS server (y) or a client (n)' 'y'
   		 	if [ $? = 1 ]; then
   		     	# Install the NFS server (you can check the status of the server via systemctl nfs-kernel-server)
   		     	sudo apt install nfs-kernel-server
   		     	sudo ufw allow nfs
   		     	# Create the NFS shares (you can change these shares yourself if you so choose)
   		     	sudo mkdir /exports
   		     	while true; do
   		         	reprompt_var "What do you want to call the NFS shares?"
   		         	share_names="$reprompt_value"
   		         	sudo mkdir /exports/$share_names
   		         	prompt 'Do you want to stop now?'
   		         	if [ $? -eq 1 ]; then
   		             	break
   		         	fi
   		     	done
   		     	# Move the /etc/exports file to another place so we can create a fresh file and keep the contents of the original one
   		     	sudo mv /etc/exports /etc/exports.orig
   		     	# Create a new /etc/exports file and put in the shares
   		     	while true; do
   		         	reprompt_var "What is the name of one of the shares you created above?"
   		         	share1="$reprompt_value"
       				 	reprompt_var "What is the name of the second share you created above?"
   			         	share2="$reprompt_value"
  					 	reprompt_var "What are the file permissions you want to put on this dir ?"
       				 	perm=$reprompt_value
   				 	reprompt_var "What is are the file permissions you want to put on this dir ?"
   				 	perm2=$reprompt_value
   				 	sudo touch /etc/exports
  					 	echo "/exports/$share1 $ip($perm,no_subtree_check)" >> /etc/exports
   				 	echo "/exports/$share2 $ip($perm2,no_subtree_check)" >> /etc/exports
      				 prompt 'Do you want to stop now?'
      				 if [ $? -eq 1 ]; then
           			 break
       				 fi
  					 done
 				  	 # Restart NFS server
   				 sudo systemctl restart nfs-kernel-server
  				 sudo systemctl start nfs-kernel-server.service
   				 echo "Enabled!"
   			 else
   				 # Set up NFS Client App
   				 sudo apt install nfs-common
   				 sudo mkdir /mnt/nfs
   				 while true; do
       					 reprompt_var "What is the name of one of the shares you want to mount to?"
       					 mount1="$reprompt_value"
       					 reprompt_var "What is the name of the second share you want to mount to?"
       					 mount2="$reprompt_value"
       					 sudo mkdir /mnt/nfs/$mount1
       					 sudo mkdir /mnt/nfs/$mount2
       				 prompt 'Do you want to stop now?'
       				 if [ $? -eq 1 ]; then
           				 break
       				 fi
   				 done
   				 prompt 'Do you want to configure the mounting process to be automatic (y) or manual (n)? Remember to check if anything is mounted using df -h.' 'y'
   				 if [ $? = 1 ]; then
       				 # Configuring and setting up autofs
       				 while true; do
           				 reprompt_var "What directories do you want to remove?"
           				 mounts="$reprompt_value"
           				 sudo rm -r $mounts
           				 prompt 'Do you want to stop now?'
           				 if [ $? -eq 1 ]; then
               				 break
           				 fi
       				 done
       				 # Install autofs
       				 sudo apt install autofs
       				 # Configure autofs files (auto.master and auto.nfs) makes sure to look at a specific file to be in the mount
       				 echo "/mnt/nfs /etc/auto.nfs --ghost --timeout=60" >> /etc/auto.master
       				 while true; do
           				 # Configure auto.nfs
           				 reprompt_var "What is the IP address of the server you want to connect to?"
           				 serverip="$reprompt_value"
           				 reprompt_var "What is the directory you want to make sure can be mounted?"
           				 dirmount="$reprompt_value"
           				 reprompt_var "What permissions do you want to have on this file? (ro, rw, etc.)"
           				 perms="$reprompt_value"
           				 echo "$dirmount -fstype=nfs4,$perms $serverip:/exports/$dirmount" >> /etc/auto.nfs
           				 prompt 'Do you want to stop now?'
           				 if [ $? -eq 1 ]; then
               				 break
           				 fi
       				 done
       				 # Make sure autofs is working
       				 sudo systemctl restart autofs
       				 echo 'Make sure the mounts are functioning properly. Remember to list the storages/directories for autofs to start working and use df -h to show the mounts. After 60 seconds, the mount will shut off. To verify the unmounting service, use the mount | grep nfs command and watch until the mounts drop (if you so choose to).'
   				 else
       				 # Mount the NFS export
       				 while true; do
           				 reprompt_var "What is the IP address you want to connect to?"
           				 NFS_server_ip="$reprompt_value"
           				 reprompt_var "What directory do you want to connect to?"
           				 NFS_dir="$reprompt_value"
           				 reprompt_var "What directory are you connecting to on your computer?"
           				 NFS_mount="$reprompt_value"
           				 sudo mount $NFS_server_ip:/exports/$NFS_dir /mnt/nfs/$NFS_mount
           				 prompt 'Do you want to stop now?'
           				 if [ $? -eq 1 ]; then
               				 break
           				 fi
       				 done
       				 echo 'To unmount, use "sudo umount /mnt/nfs/<directory you connected to>".'
       				 echo 'NFS has been configured :)'
   				 fi
   			 fi
   		 else
   				 systemctl stop nfs-kernel-server
   				 systemctl disable nfs-kernel-server
   				 apt-get purge nfs-kernel-server -y
   				 ufw delete allow nfs-kernel-server
   				 systemctl stop nfs-common
   				 systemctl disable nfs-common
   				 apt-get purge nfs-common
   				 ufw delete allow nfs-common
   				 echo "Disabled!"
   		 fi
   		 ;;



   	 #Kernel
   	 18)


   	 prompt 'Do you want to configure Kernel Parameters ?' 'y'
   	 if [ $? = 1 ]; then
   	 
   		 echo "net.ipv4.conf.all.rp_filter=1" >> $kernel_params
   		 echo "net.ipv4.conf.all.accept_source_route=0" >> $kernel_params
        		 echo "net.ipv4.icmp_echo_ignore_broadcasts=1" >> $kernel_params
   		 echo "net.ipv4.icmp_ignore_bogus_error_messages=1" >> $kernel_params
   		 echo "net.ipv4.icmp_ignore_bogus_error_messages=1" >> $kernel_params
   		 echo "kernel.exec-shield=1" >> $kernel_params
   		 echo "kernel.randomize_va_space=1" >> $kernel_params
   		 echo "kernel.randomize_va_space=1" >> $kernel_params
   		 echo "net.ipv4.tcp_syncookies=1" >> $kernel_params
   		 echo "net.ipv4.tcp_max_syn_backlog=2048" >> $kernel_params
   		 echo "net.ipv4.tcp_synack_retries=3" >> $kernel_params
         echo "kernel.dmesg_restrict=1" >> $kernel_params

   	 else
   		 echo "okay my bad :("
   	 fi
   	 ;;




   	#Cron
   	19)
    
   	 while true; do
   	 prompt 'Do you want to look at users crontabs  ?'
   	 if [ $? = 1 ]; then
   		 for user in $(cut -f1 -d: /etc/passwd); do
   			 echo "Crontab for $user:"
   			 sudo crontab -u $user -l
   			 echo ""
   		 done
    
   		 prompt 'Do you want to print out the contents of a users crontab?'
   		 if [ $? = 1 ]; then
    
   			 reprompt_var 'Name of users cron tab you want to print out'
   			 users_crontab="$reprompt_value"
   	 
    
   			 crontab -u $users_crontab -l
   		 else
   			 echo 'okay next step'
   	 
   		 fi
    
   		 prompt 'Do you want to edit a crontab ?'
   		 if [ $? = 1 ]; then
    
   			 reprompt_var 'Name of users cron tab you want to edit'
   			 users_crontab="$reprompt_value"
   	 
   			 crontab -u $users_crontab -e
    
   	     	 
   		 else
   			 prompt 'Do you want to delete a cron job or continue?'
   			 if [ $? = 1 ]; then
   					 
   				 crontab -u $users_crontab -r
   			 else
   				 echo "Happy Hacking!"
    
   			 fi
   		 fi    

   	 else

   		 break 2

   	 fi
   	 done
   		 prompt 'Do you want to look at crontabs in depth ?'
   		 if [ $? = 1 ]; then
    
   		   while true; do
   			 PS3="Select a cron tab to investigate: "
   			 options=("/etc/crontab" "/etc/cron.d/" "/etc/cron.daily/" "/etc/cron.hourly/" "/etc/cron.weekly/" "/etc/cron.monthly/" "/var/spool/cron/crontabs/" "/var/spool/cron/   	 atjobs/" "/etc/anacrontab" "/etc/cron.deny" "/etc/cron.allow" "Quit")
   		 
   			 select crontabs in ${options[@]}
   			 do
   				 case $crontabs in
   		 
   		 
   					 "/etc/crontab")
   		 
   						 less /etc/crontab
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   					 
   							 nano /etc/crontab
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   					 
   					 "/etc/cron.d/")
   						 ls /etc/cron.d
   						 reprompt_var 'List crontab you want to inspect'
   						 crondtab="$reprompt_value"
   						 
   						 less /etc/cron.d/$crondtab
   				 
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   					 
   							 nano /etc/cron.d/$crondtab
   							 echo "Happy Hacking!"
   						 else
   					 
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   				 
   					 "/etc/cron.daily/")
   			 
   						 ls /etc/cron.daily/
   						 reprompt_var 'List crontab you want to inspect'
   						 crondaily="$reprompt_value"
   				 
   						 less /etc/cron.daily/$crondaily
   				 
   						 prompt ' Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /etc/cron.daily/$crondaily
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   				 
   					 "/etc/cron.hourly/")
   						 ls /etc/cron.hourly/
   						 reprompt_var 'List crontab you want to inspect'
   						 cronhourly="$reprompt_value"
   				 
   						 less /etc/cron.hourly/$cronhourly
   				 
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /etc/cron.daily/$cronhourly
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   					 "/etc/cron.weekly/")
   						 ls /etc/cron.weekly/
   						 reprompt_var 'List crontab you want to inspect'
   						 cronweekly="$reprompt_value"
   				 
   						 less /etc/cron.weekly/$cronweekly
   				 
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /etc/cron.weekly/$cronweekly
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   					 "/etc/cron.monthly/")
   						 ls /etc/cron.monthly/
   						 reprompt_var 'List crontab you want to inspect'
   						 cronmonthly="$reprompt_value"
   				 
   						 less /etc/cron.monthly/$cronmonthly
   				 
   						 prompt ' Do you want to edit a cron job ? '
   						 if [ $? = 1 ]; then
   							 nano /etc/cron.monthly/$cronmonthly
   					 
   						 else
   							 echo "Happy Hacking!"
   				 
   						 fi
   						 ;;
   				 
   					 "/var/spool/cron/crontabs/")
   						 ls /var/spool/cron/crontabs/
   						 reprompt_var ' List the crontab you want to inspect'
   						 spoolcrontabs="$reprompt_value"
   					 
   						 less /var/spool/cron/crontabs/$spoolcrontabs
   				 
   						 prompt 'Do you want to edit or delete a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /var/spool/cron/crontabs/$spoolcrontabs
   					 
   						 else
   							 crontab -u $spoolcrontabs -r
   							 echo "Happy Hacking !"
   						 fi
   						 ;;
   				 
   					 "/var/spool/cron/atjobs/")
   						 ls /var/spool/cron/atjobs
   						 reprompt_var ' List the crontab you want to inspect'
   						 atjobs="$reprompt_value"
   				 
   						 less /var/spool/cron/atjobs/$atjobs
   				 
   						 prompt 'Do you want to edit or delete a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /var/spool/cron/atjobs/$atjobs
   					 
   						 else
   							 crontab -u $atjobs -r
   							 echo "Happy Hacking !"
   			 
   					 
   						 fi
   						 ;;
   				 
   				 
   					 "/etc/anacrontab")
   						 less /etc/anacrontab
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   							 
   							  nano /etc/anacrontab
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   					 
   					 "/etc/cron.deny")
   						 ls /etc/cron.deny
   					 
   						 less /etc/cron.deny
   					 
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /etc/cron.deny
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   				 
   					 "/etc/cron.allow")
   						 ls /etc/cron.allow
   					 
   						 less /etc/cron.allow
   				 
   						 prompt 'Do you want to edit a cron job ?'
   						 if [ $? = 1 ]; then
   							 nano /etc/cron.allow
   						 else
   							 echo "Happy Hacking!"
   						 fi
   						 ;;
   			 
   			 
   					 "Quit")
   				 
   						 break 2
   						 ;;
   				 
   					 *)
   						 echo "Invalid Response"
   						 ;;   		 
   				 
   			 
   							 
   				 esac
   			 done
   		   done    
   		 fi
    
   		 sudo echo "ALL" >> /etc/cron.deny
   		 
   		 prompt 'Do you want to look at the syslogs for cron'
   		 if [ $? = 1 ]; then
   			 
   			  sudo cat /var/log/syslog | grep cron | tee -a cron.log
   			 
   			  echo "Thank you and Happy Hacking !"
   		 else
   			 echo "Happy Hacking!"
   		 fi
               		 ;;
               		 
        	#Add your own scripts to cron + Rsync backup using SSH
        	20)
       	 
       			 echo ' Make sure to create a backups folder onto another machine like a server or another desktop to backup all of your data securly and safely. i.e mkdir /home/<curentuser/backups as well as create an ssh folder, mkdir .ssh then cp backup_keys.pub ~/.ssh/authorized_keys '
       			 prompt 'Do you want to add a Backup script with Rsync(y) or add your own script (n) ( script fromat is * * * * * /bin/sh <dir to script> ?'
       			 if [ $? = 1 ]; then
       			 
       				 #create keys for automation of rsync (client needs private key, server needs public key
       				 ssh-keygen -t ecdsa -f backup_keys
       				 mv backup_keys /root
       				 
       				 
       				 #copy over the public key to the server
   				 reprompt_var 'Username you are backing up to: '
       				 recievinguser="$reprompt_value"
       				 
       				 reprompt_var 'IP address of the receiving user: '
       				 recievingIP="$reprompt_value"
       				 
       				 reprompt_var 'Directory of the other machine you want to store the public keys to: '
       				 keydir="$reprompt_value"
       			 
       				 scp backup_keys.pub $recievinguser@$recievingIP:$keydir
       				 
       				 mv backup_keys.pub /root
       				 
       				 
       				 
       				 
       				 
       				 
       				 #start rsync ( put which directory you want to backup )
       				 while true; do
       					 reprompt_var 'Path to the directory you want to backup'
       					 rsyncbackup="$reprompt_value"
       				 
       					 reprompt_var 'Username you are backing up to: '
       					 recievinguser="$reprompt_value"
       				 
       					 reprompt_var 'IP address of the receiving user: '
       					 recievingIP="$reprompt_value"
       				 
       					 reprompt_var 'Directory of the other machine you are backing up to: '
       					 backupdir="$reprompt_value"
       				 
       				 
       					 #lets us use rsync using another service ex ssh, ftp,
      	 
       					 rsync -av -e "ssh -i /root/backup_keys" $rsyncbackup $recievinguser@$recievingIP:$backupdir

       					 
       					 
       				 
       				 prompt ' Do you want to stop ? '
       				 if [ $? = 1 ]; then
       				 break
       				 fi
       				 done
       				 
       				 
       			 else
       			 
       		     	 crontab -e
      				 echo 'Happy automation!'
      			 fi
       				 ;;
       	 
       				 
       				 
       			 
       			 
       	 
        	#DNS Server
        	#21)
       	 
        	#NTP ( Network Time Protocol )
        	#22)
              		 
              		 
	#List files with high file permissions
	23)
    
    

  	  prompt 'Do you want to list files with high file permissions ?' 'y'
  	  if [ $? = 1 ]; then

  	  	find /home/ -perm 700 -type f

  	  	echo "found files!"


  	  	echo "Found $(wc -l < high-perm-file) files with permissions 700 or higher in /home/!"

  	  else
  			 echo -e "Then why did you click the button dum dum >:("
  	  fi
       		 ;;
      		 
      		 
      		 
      		 
	#Delete Bad Software
	24)
  	  for software in "${bad_software[@]}";
  	  do
  	  	 sudo apt-get purge "$software"
  	 
  	 
  	  done
  	  echo 'Software has been deleted'
  	  echo 'Make sure to check manually using synaptic package manager'
  	  ;;
  	 
  	 
	#checking perms for important files
	25)
    
    

  	  prompt 'fix unexpected perms in passwd, group, gshadow, and shadow ?' 'y'
  	  if [ $? = 1 ]; then

   		 sudo chmod 640 /etc/passwd
   		 sudo chmod 640 /etc/group  
   		 sudo chmod 640 /etc/shadow
   		 sudo chmod 640 /etc/gshadow
   		 sudo chmod -R 440 /etc/ssh
   		 sudo chmod -R 440 /var/log
   		 sudo chmod 700 /etc/profile
   		 sudo chmod 700 /etc/hosts.allow
   		 sudo chmod 700 /etc/mtab
   		 sudo chmod 700 /etc/utmp
   		 sudo chmod 700 /var/log/wtmp
   		 sudo chmod 700 /var/run/syslog.pid
   		 sudo chmod 644 /etc/fstab
   		 sudo chmod 600 /etc/sudoers
    
   		 echo "yayy it has been done"
   		 
   		 
  	  else
  	      echo "okay we won't do it then -_-"
  	  fi
  	  ;;
      		 
      		 
	#clear /etc/rc.local
	26)
    
    

  	  echo 'exit 0' > /etc/rc.local
  	  echo 'cleared /etc/rc.local'
       		 ;;
      		 
      		 
      		 
      		 
	# List all running services
	27)
  	  prompt 'Do you want to list all running services' 'y'
  	  if [ $? = 1 ]; then

  		  systemctl list-units --type=service --state=active
  		  echo -e "Here’s the goods sir, you’re welcome :3"
  	  else
  	   	 systemctl list-units –type=service;
  	  echo -e "not running but l;ist of services :p"

  	  fi
       		 ;;   		 
      		 
      		 

	#run rkhunter
	28)


  	  prompt "Do you want to install and run rkhunter?"
     	   if [ $? -eq 1 ]; then

  		  sudo apt-get install rkhunter -y
  	 
  		  rkhunter --update
  	 
  		  rkhunter --check --sk
  	 
  		  echo -e "Thank you for keeping your system safe from the boogie man!"

    
  	  else
     			 echo -e "Okay have a good day sorry for bothering you :<"
  	  fi
  		  ;;
  	 
  	 


	#run clamav
	29)


  	  reprompt_var 'Path to scan' clamscan_path

  	  clamscan_path="$repromptvar"


  	  prompt 'Recurse?' 'y'
  	  if [ $? = 1 ]; then
  	      clamscan_params+=('--recursive')
  	  fi


  	  prompt 'Save log file?' 'y'
  	  if [ $? = 1 ]; then

  	  reprompt_var "Path to log file" clamscan_logs
  	      clamscan_logs="$repromptvar"
  	      clamscan_params+=('--log')
  	      clamscan_params+=("$clamscan_logs")

  	  fi

  	  prompt 'Only print infected files?' 'y'
  	  if [ $? = 1 ]; then

  	      clamscan_params+=('--infected')

  	  fi


  	  prompt 'Verbose output?' 'y'
  	  if [ $? = 1 ]; then
 
  	      clamscan_params+=('--verbose')
  	  fi

  	  apt-get install clamav clamtk -y

  	  prompt 'Enable freshclam service? (only needs to be done once shawty)' 'n'
  	  if [ $? = 1 ]; then
  	      systemctl enable clamav-freshclam
  	      systemctl start clamav-freshclam
  	  fi


  	  clamscan "$clamscan_path" ${clamscan_params[@]}
       		 ;;
      		 
      		 
      		 
      		 
      		 
	#run chkroot
	30)

  	  prompt 'Do you want to download and run chkrootkit?' 'y'
  	  if [ $? = 1 ]; then

  		  sudo apt install chkrootkit
    
  		  chkrootkit
  	  else
  			 echo -e "My bad Shawty I didn’t mean to play with you like that mannnnn?"
  	  fi
       		 ;;


	#List all media files
	31)

  	  reprompt_var 'Name of output file (will appear on desktop)' found_media_file
  	     		 found_media_file="$reprompt_value"
  	     		 reprompt_var 'Path to search' media_path
  	     		 media_path="$reprompt_value"
  	     		 prompt "Print files as they're found?" 'n'

  	     		 if [ $? = 1 ]; then
  	         		 echo 'Searching...'
  	         		 find "$media_path" -type f \( "${media_files[@]}" \) | tee "$found_media_file"
  	     		 else
  	         		 echo 'Searching...'
  	         		 find "$media_path" -type f \( "${media_files[@]}" \) > "$found_media_file"
  	     		 fi

  	     		 echo "Found $(wc -l < $found_media_file) media files!"
                   		 ;;


 	#Run Auditing tool Lynis
  	32)
    
   	 apt install lynis -y
   	 lynis audit system
   	 echo 'Okay you are done now, lots of stuff you need to do now huh?'
   	 
   	 
   	 ;;
   	 
    #Install AppArmor
    33)
    
   	 prompt 'Do you want to install AppArmor' 'y'
   	 if [ $? = 1 ]; then
   	 
   		 apt install apparmor-utils
   		 systemctl enable apparmor
   		 
   		 aa-unconfined
   		 prompt 'Do you want to configure an apparmor profile'
   		 if [ $? = 1 ]; then
   			 
   			 while true; do
   			 
   				 reprompt_var 'What profile do you want to generate for app armor'
   				 armorprofile="$reprompt_value"
   				 aa-genprof $armorprofile
   				 
   				 
   			 prompt ' Do you want to stop? '
   			 if [ $? = 1 ]; then
   			 break
   			 fi
   			 done   			 
   			 
   		 
   		 
   	 else
   		 echo 'Okay then'
   		 
   		 fi
   	 fi
   	 ;;
    #Edit Hosts file
    34)
    
   	 sudo nano /etc/hosts
   	 ;;
   	 
    #Edit Nameservers File
    35)
   	 
   		 sudo nano /etc/resolv.conf
   		 ;;
   		 
    #Check and Edit Repositories
    36)
    
   		 cat /etc/apt/sources.list
   		 ls /etc/apt/sources.list.d/
   		 
   		 while true; do
   			 reprompt_var 'What file do you want to inspect'
   			 file="$reprompt_var"
   			 
   			 cat /etc/apt/sources.list.d/$file
   			 
   			 prompt 'Do you want to stop now?'
           			 if [ $? -eq 1 ]; then
               			 break
           			 fi
       			 done
       			 
       			 while true; do
       				 prompt "Do you want to edit a repository?"
       				 if [ $? -eq 1 ]; then
       				 
       				  	reprompt_var 'What file/ directory ( /etc/apt/sources.list or /etc/apt/sources.list.d/file'
       				  	fileordir="$reprompt_value"
       				 	 
       				  	sudo nano $fileordir
       				 else
       				 
       			     	 prompt ' Do yo want to stop no ?'
       			     	 if [ $? -eq 1 ]; then
       			     	 break
       			     	 fi
       			      fi   	 
       			 done
       			 ;;
   			 
   			 
   			 
   			 
    #check Installed packages
    37)
    
   		 sudo apt list --installed
   		 ;;
   	 
   	 
    #Edit sudoers file to check for misconfigs
    38)
    
   	 sudo visudo
   	 
   	 chmod 600 /etc/sudoers
   	 
   	 echo 'Done configuring and securing the sudoers file'
   	 ;;
   	 
    #check for illegitimate software yourself
    39)
    
   	 sudo service --status-all | grep "+"    
   	 
   	 prompt 'Do you want to disable or delete a service ?'
   	 if [ $? = 1 ]; then
   	 
   		 
   		 reprompt_var "What service would you like to disable ?"
   		 service="$reprompt_value"
   		 
   		 sudo systemctl stop $service
   		 
   	 else
   	 
   		 reprompt_var "What service would you like to delete?"
   		 service="$reprompt_value"
   		 
   		 sudo apt-get purge $service
   	 fi
   	 ;;
    
    #Password Aging Policies
    40)
    
   	 sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90' /etc/login.defs
   	 sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   10' /etc/login.defs
   	 sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE     7'  /etc/login.defs
   	 echo "Password Aging Policies have been set!"
   	 ;;
   	 
    #Password Authentication and strong Passwords
    41)
   	 
   	 #password authentication
   	 echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
   	 
   	 #force strong passwords
   	 sudo apt-get install libpam-cracklib -y
   	 sudo sed -i '1 s/^/password requisite pam_cracklib.so retry=3 minlen=8 difok=3 reject_username minclass=3 maxrepeat=2 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1\n/' /etc/pam.d/common-password
   	 sudo sed -i '2 s/^/password requisite pam_pwhistory.so use_authtok remember=24\n/' /etc/pam.d/common-password
   	 sudo sed -i '3 s/^/password [success=1 default=ignore] pam-unix.so obscure use_authtok sha512 shadow\n/' /etc/pam.d/common-password
   	 
   	 echo "Password authentication and settings have been enabled!"
   	 ;;
   	 
    #Systemctl Configurations
    42)
    
   	 #configure sysctl.conf
   	 #add presence checks for all of these
   	 sudo chmod 702 /etc/sysctl.conf
   	 #ip spoofing protection
   	 echo "net.ipv4.conf.default.rp_filter = 1" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.all.rp_filter = 1" >> /etc/sysctl.conf
   	 #block syn attacks
   	 echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
   	 echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.conf
   	 echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
   	 echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.conf
   	 #control ip packet forwarding
   	 echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf
   	 #ignore icmp redirects
   	 echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.conf
   	 #ignore send redirects
   	 echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.conf
   	 #disable source packet routing
   	 echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.conf
   	 #log martians
   	 echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.conf
   	 echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.conf
   	 #ignore icmp broadcast requests
   	 echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.conf
   	 #ignore directed pings
   	 echo "net.ipv4.icmp_echo_ignore_all = 1" >> /etc/sysctl.conf
   	 echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
   	 echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf
   	 #disable ipv6 :(
   	 echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
   	 #deny redirects
   	 echo "net.ipv4.conf.all.secure_redirects = 0" >> /etc/sysctl.conf
   	 #log packets with impossible addresses to kernel log
   	 echo "net.ipv4.conf.default.secure_redirects = 0" >> /etc/sysctl.conf
   	 #ipv6 configurations
   	 echo "net.ipv6.conf.default.router_solicitations = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.autoconf = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.dad_transmits = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.max_addresses = 1" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.all.send redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.all.accept redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.all.secure redirects = 0" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.all.log martians = 1" >> /etc/sysctl.conf
   	 echo "net.ipv4.conf.all.rp filter = 1" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.all.accept ra = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.default.accept_ra = 0" >> /etc/sysctl.conf
   	 echo "net.ipv6.conf.all.accept redirects = 0" >> /etc/sysctl.conf
   	 echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
   	 echo "kernel.perf_event_paranoid = 3" >> /etc/sysctl.conf
   	 #panic when out of memory
   	 echo "vm.panic_on_oom = 1" >> /etc/sysctl.conf
   	 #reboot system 10 seconds after panic
   	 echo "kernel.panic = 10" >> /etc/sysctl.conf
   	 #apply new sysctl.conf settings
   	 sudo chmod 700 /etc/sysctl.conf
   	 sudo sysctl -p
   	 #do the thing
   	 sudo sysctl -w net.ipv4.ip.forward=0
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.conf.all.send_redirects=0
   	 sudo sysctl -w net.ipv4.conf.default.send redirects=0
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
   	 sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
   	 sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
   	 sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.conf.all.log_martians=1
   	 sudo sysctl -w net.ipv4.conf.default.log_martians=1
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.icmp.echo_ignore_broadcasts=1
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.conf.all.rp_filter=1
   	 sudo sysctl -w net.ipv4.conf.default.rp_filter=1
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv4.tcp.syncookies=1
   	 sudo sysctl -w net.ipv4.route.flush=1
   	 sudo sysctl -w net.ipv6.conf.all.accept_ra=0
   	 sudo sysctl -w net.ipv6.conf.default.accept_ra=0
   	 sudo sysctl -w net.ipv6.route.flush=1   		 
   	 sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
   	 sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
   	 sudo sysctl -w net.ipv6.route.flush=1
   	 sudo sysctl -w kernel.randomize_va_space=2
   	 sudo sysctl -w kernel.perf_event_paranoid=3
   	 sudo sysctl -p
   	 
   	 echo "systemctl has been configured"
   	 ;;
   	 
   	 
    #Other Sys configs (auditing, hosts, DCCP, ntp, motd, core dumps, ip spoofing
    43)
    
    
   	 sudo apt install aide-common
   	 sudo apt install auditd
   	 #intrusion detection enabled
   	 aideinit

   	 #configure common-auth
   	 #add a check for if this is already in here
   	 sudo chmod 702 /etc/pam.d/common-auth
   	 sudo chmod 700 /etc/pam.d/common-auth

   	 #enable auditing
   	 sudo auditctl -e 1
   	 
   	 #auditing
   	 sudo chmod 777 /etc/audit/auditd.conf
   	 echo "max_log_file = 16384" >> /etc/audit/auditd.conf
   	 echo "space_left_action = email" >> /etc/audit/auditd.conf
   	 echo "action mail acct = root" >> /etc/audit/auditd.conf
   	 echo "admin_space_left_action = halt" >> /etc/audit/auditd.conf
   	 echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
   	 sudo chmod 700 /etc/audit/auditd.conf
   	 systemctl reload auditd
   	 sudo chmod 777 /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time- change" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> //etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S clock_settime -k time-change -w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
   	 echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
   	 echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
   	 echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
   	 echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
   	 echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
   	 echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
   	 echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
   	 echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
   	 echo "-w /etc/sysconfig/network -p wa -k system-locale" >> //etc/audit/audit.rules
   	 echo "-w /etc/apparmor/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
   	 echo "-w /etc/apparmor.d/ -p wa -k MAC-policy" >> /etc/audit/audit.rules
   	 echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
   	 echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
   	 echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules
   	 echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
   	 echo "-w /var/log/wtmp -p wa -k logins" >> /etc/audit/audit.rules
   	 echo "-w /var/log/btmp -p wa -k logins" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!    =4294967295 -k access" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
   	 echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
   	 echo "-w /etc/sudoers.d/ -p wa -k scope" >> /etc/audit/audit.rules
   	 echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
   	 echo "-w /sbin/insmod -p x -k modules" >> /etc/audit/audit.rules
   	 echo "-w /sbin/rmmod -p x -k modules" >> /etc/audit/audit.rules
   	 echo "-w /sbin/modprobe -p x -k modules" >> //etc/audit/audit.rules
   	 echo "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
   	 sudo chmod 700 /etc/audit/auditd.conf
   	 sudo chmod 777 /etc/audit/.rules
   	 echo "-e 2" >> /etc/audit/.rules
   	 sudo chmod 700 /etc/audit/.rules
   	 
   	 sudo reload auditd
   	 echo "Auditing has been configured"
   	 
   	 #ip spoofing
   	 sudo chmod 702 /etc/host.conf
   	 echo "order bind,hosts" >> /etc/host.conf
   	 echo "nospoof on" >> /etc/host.conf
   	 sudo chmod 700 /etc/host.conf

   	 #restrict core dumps
   	 sudo chmod 702 /etc/security/limits.conf
   	 echo "* hard core" >> /etc/security/limits.conf
   	 sudo chmod 700 /etc/security/limits.conf
   	 sudo chmod 702 /etc/sysctl.conf
   	 echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf
   	 sudo chmod 700 /etc/sysctl.conf
   	 sudo sysctl -w fs.suid_dumpable=0
   	 
   	 #Config hosts.deny
   	 sudo chmod 777 /etc/hosts.deny
   	 echo "ALL: ALL" >> /etc/hosts.deny
   	 sudo chmod 700 /etc/hosts.deny
   	 
   	 #disable IPv6
   	 sudo chmod 777 /etc/default/grub
   	 echo 'GRUB_CMDLINE_LINUX="ipv6.disable=1"' >> /etc/default/grub
   	 echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
   	 sudo chmod 700 /etc/default/grub
   	 update-grub
   	 
   	 echo 'Extra system configs have been enabled!'
   	 ;;
   	 
    #Shared memory
    44)
    
   	 echo "tmpfs  /run/shm	tmpfs  defaults,noexec,nosuid	0	0" >> /etc/fstab
   	 ;;

    45)
    
   	 prompt 'View files immutables or Directory immutables'
   	 if [ $? = 1 ]; then
   	    sudo find / -type f -exec lsattr {} + 2>/dev/null | awk '$1 ~ /i/ {print $2}' 		 
   	 else
   	    sudo find / -type d -exec lsattr {} + 2>/dev/null | awk '$1 ~ /i/ {print $2}'

   	 fi
   	 ;;
  #find all suid/sgid bits 
    46)
     find / \( -perm -4000 -o -perm -2000 \) -exec ls -ld {} \; 2>/dev/null
     ;;
   #Sticky bits
    47)
     find / -type d -perm -1000 -exec ls -lda {} \; 2>/dev/null
     ;;

   #htop for processes
    48)
     apt install htop
     htop 
     ;;
   #list masked services
    49)
     systemctl list-unit-files --state=masked
     sudo systemctl mask kdump --now
     ;;
   #debsums 
    50)
     apt install debsums 
     debsums -s 
     debsums -c
     ;;

   #kernel modules 
    51) 
     lsmod
     ;;
   #check if all users have a password through /etc/shadow
    52)
     awk -F: '!$2 {print $1}' /etc/shadow
     ;;
   #check if there are blank passwords for any users
    53)
     PAM_FILE="/etc/pam.d/common-password"

     # Check if the file contains 'nullok'
     if grep -q "nullok" "$PAM_FILE"; then
         # Backup the original file before modifying it
         cp "$PAM_FILE" "$PAM_FILE.bak"
         echo "Backup created: $PAM_FILE.bak"
        
         # Remove lines containing 'nullok'
         sudo sed -i '/nullok/ { s/\s*nullok\s*/ /g }' "$PAM_FILE"
         echo "Lines containing 'nullok' have been removed."
     else
         echo "'nullok' not found in $PAM_FILE. No changes made."
     fi

     ;;
   #directory perms 
    54)
     sudo chgrp syslog /var/log
     sudo chown root /var/log
     sudo chown :root /usr/bin/journalctl
     sudo chown root /usr/bin/journalctl
     sudo chgrp adm /var/log/syslog
     sudo chown syslog /var/log/syslog
     sudo find /lib /usr/lib /lib64 ! -group root -type d -exec chgrp root '{}' \;
     sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec chgrp root '{}' \;
     sudo find /lib /usr/lib /lib64 ! -user root -type d -exec chown root '{}' \;
     sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec chown root '{}' \;
     sudo chmod 0755 /var/log
     sudo find /lib /lib64 /usr/lib -perm /022 -type f -exec chmod 755 '{}' \;
     sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec chmod 755 '{}' \;
     echo "Done"
     ;;

    #dirs to maybe add sticky bit to 
     55) 
      sudo find / -type d -perm -002 ! -perm -1000
      echo "If any pop up do sudo chmod +t to change this"
      ;;

    #configure to use pam_faillock
     56)
   
      # Define the PAM and faillock files
      PAM_FILE="/etc/pam.d/common-auth"
      FAILLLOCK_FILE="/etc/security/faillock.conf"

      # Append the PAM lines directly to the PAM file
      echo "auth [default=die] pam_faillock.so authfail" | sudo tee -a "$PAM_FILE" > /dev/null
      echo "auth sufficient pam_faillock.so authsucc" | sudo tee -a "$PAM_FILE" > /dev/null
      echo "auth required pam_faildelay.so delay=4000000" | sudo tee -a "$PAM_FILE" > /dev/null

      # Append the faillock lines directly to the faillock.conf file
      echo "audit" | sudo tee -a "$FAILLLOCK_FILE" > /dev/null
      echo "silent" | sudo tee -a "$FAILLLOCK_FILE" > /dev/null
      echo "deny = 3" | sudo tee -a "$FAILLLOCK_FILE" > /dev/null
      echo "fail_interval = 900" | sudo tee -a "$FAILLLOCK_FILE" > /dev/null
      echo "unlock_time = 0" | sudo tee -a "$FAILLLOCK_FILE" > /dev/null

      # Define the files to modify
      PAM_LOGIN_FILE="/etc/pam.d/login"
      LIMITS_FILE="/etc/security/limits.conf"

      # Add the line for providing feedback on last login to the PAM login file
      echo "session required pam_lastlog.so showfailed" | sudo tee -a "$PAM_LOGIN_FILE" > /dev/null

      # Add the line to limit the number of concurrent sessions to 10 in limits.conf
      echo "* hard maxlogins 10" | sudo tee -a "$LIMITS_FILE" > /dev/null
      ;;

     57) 
     #even more password stuff 
      sudo apt-get install -y libpam-pwquality

      # Step 2: Configure /etc/security/pwquality.conf
      echo "Configuring /etc/security/pwquality.conf..."
      echo "dictcheck = 1" | sudo tee -a /etc/security/pwquality.conf > /dev/null
      echo "minlen = 15" | sudo tee -a /etc/security/pwquality.conf > /dev/null
      echo "difok = 8" | sudo tee -a /etc/security/pwquality.conf > /dev/null
      echo "enforcing = 1" | sudo tee -a /etc/security/pwquality.conf > /dev/null
      echo "lcredit = -1" | sudo tee -a /etc/security/pwquality.conf > /dev/null
      echo "dcredit = -1" | sudo tee -a /etc/security/pwquality.conf > /dev/null
      echo "ocredit = -1" | sudo tee -a /etc/security/pwquality.conf > /dev/null

        # Step 3: Configure /etc/pam.d/common-password
      echo "Configuring /etc/pam.d/common-password..."
      echo "password requisite pam_pwquality.so retry=3" | sudo tee -a /etc/pam.d/common-password > /dev/null
      echo "password [success=1 default=ignore] pam_unix.so obscure sha512 shadow remember=5 rounds=5000" | sudo tee -a /etc/pam.d/common-password > /dev/null

        # Step 4: Configure /etc/login.defs
      echo "Configuring /etc/login.defs..."
      echo "ENCRYPT_METHOD SHA512" | sudo tee -a /etc/login.defs > /dev/null
      echo "PASS_MIN_DAYS 1" | sudo tee -a /etc/login.defs > /dev/null
      echo "UMASK 077" | sudo tee -a /etc/login.defs > /dev/null

        # Step 5: Lock the root account
      echo "Locking the root account..."
      sudo passwd -l root

        # Step 6: Set the default password expiration policy to 35 days
      echo "Setting default password expiration to 35 days..."
      sudo useradd -D -f 35
      ;;
# check if mult users with same uid 
     58)
      awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd
      ;;
	# Exit
   		 99)
       		 echo 'Thank you for using this script!'
       		 exit 0
       		 
       		 ;;
      		 

   	 # Invalid option
   	 *)
   		 echo "Unknown option $input"
   		 ;;
    esac
}

while true; do menu; done

 




