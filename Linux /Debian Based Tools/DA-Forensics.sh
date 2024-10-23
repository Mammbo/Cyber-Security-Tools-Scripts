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

function menu {

	echo ' 1) find UID                      		 21)   '   
	echo ' 2) find GID        				 22)  '
	echo ' 3) List IPS,everything Lsof  			 23)                  		  '
	echo ' 4) List all Running Processes            	24)   '
	echo ' 5) List all Media Files                  	25)   '
	echo ' 6) List all active ports	'
	echo ' 7) List all Running Services   '
	echo ' 8) Get the Hash of a given file '
	echo ' 9) Hard drive information'
	echo '10) List current UFW configurations	'
	echo '11) List all groups	'
	echo '12) Configure the Hosts file (DNS)'
	echo '13) List Users in a sambashare'
	echo '14) cat /etc/passwd file'
	echo '15) See owner of file'
	echo '16) '
	echo '17) '
	echo '18) '
	echo '19) '
	echo '20) '
	echo
	echo '99) Exit Script'
	read -r -p '> ' input

	case $((input)) in
    
    
    
	#Find UID
	1)
   	 while true; do
  		  reprompt_var 'What user are we trying to find the uid and gids for?'
  		  user="$reprompt_vlaue"
  		  id -u $user
  	 prompt 'Are you done?'
  	 if [ $? = 1 ]; then
  	 break
  	 fi
  	 done
  		  ;;
  		 
  		 
   #Find GID
   2)
  	 while true; do
  		  reprompt_var 'What user are we trying to find the uid and gids for?'
  		  user="$reprompt_vlaue"
  		  id -g $user
  	 prompt 'Are you done?'
  	 if [ $? = 1 ]; then
  	 break
  	 fi
  	 done
  	 
  	 
  		  ;;
  		 
  		 
   # IPS  
   3)
   
  	 lsof -i
  	 ;;
  	 
  	 
   #List all running Processes
   4)
   
  	 ps -aux | less | tee -a process.log
  	 pstree
  	 top
  	 ;;
  	 
    
   #List all Media Files
   5)
   
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

  	     		 echo "Found $(wc -l < "$found_media_file") media files!"
                    	;;

   
   #List all active Ports
   6)
   
  	 lsof -i -P -n | grep LISTEN | tee -a ports.txt
 
  	 ss | tee -a ports.txt
  	 
  	 echo 'Thank you for your time '
  	 
  	 ;;
  	 
  	 
   #List all Running Services
   7)
  	  prompt 'Do you want to list all running services' 'y'
  	  if [ $? = 1 ]; then

  		  systemctl list-units --type=service --state=active
  		  echo -e "Here’s the goods sir, you’re welcome :3"
  	  else
  	   	 systemctl list-units –type=service;
  	      echo -e "not running but list of services :p"

  	  fi
       		 ;;  	 
       		 
	#Get the Hash of a file
	8)
    
   		 reprompt_var 'What hash are you looking for (sha256sum) or word if you choose ? '
   		 hash="$reprompt_value"
   		 reprompt_var 'What directory are you trying to search? ( ex: /)'
   		 dir="$reprompt_value"
   		 
   		 find $dir -type f -exec $hash {} \; | tee -a file_hashes.txt
   		 
   		 sort file_hashes.txt | uniq -d -w 64 > identical_hashes.txt
   		 
   		 while read -r hash; do
   			 grep "$hash" file_hashes.txt
   		 done < identical_hashes.txt > identical_files.txt
   		 
   		 echo 'thank you for solving this problem :)'
        	;;
       	 
   #Find our drive information
   9)
  		 #finds out drive information
  		 sudo blkid
  		 ;;
  		 
   # Lists current UFW Configurations
   10)
   
  		 sudo ufw status verbose
  		 sudo ufw status numbered
  		 ;;
  		 
   # List groups
   11)
  		 sudo cat /etc/group
  		 ;;
   
   #change hosts file
   12)
  		 sudo nano /etc/hosts
   		 ;;
   # List Users in a sambashare
   13)
  		 sudo pdbedit -L -v
  		 ;;

   # cat /etc/passwd
   14)
   
  		 cat /etc/passwd
  		 ;;
   
   #See owner of file
   15)
  	 
  		 reprompt_var 'File you want to look into?'
  		 file="$reprompt_value"
  		 
  		 stat $file
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








