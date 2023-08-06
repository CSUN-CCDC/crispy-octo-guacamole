#!/usr/bin/env bash

set -e

FILE="inventory.txt"

# Get OS info
if [ $(command -v hostnamectl) ]; then
    hostnamectl | tee $FILE
elif [ -r /etc/os-release ]; then
    cat /etc/os-release | tee $FILE
elif [ -r /etc/lsb-release ]; then
    cat /etc/lsb-release | tee $FILE
else
    echo "Was not able to get OS info"
    exit 1
fi

# Get IP information
if [ $(command -v ip) ]; then
    ip -brief address | tee $FILE
elif [ $(command -v ifconfig) ]; then
    ifconfig | tee $FILE
else
    echo "Neither ip nor ifconfig are installed; quitting."
    exit 1
fi

# Get open ports
if [ $(command -v nmap) ]; then
    nmap -sV localhost | tee $FILE
elif [ $(command -v netstat) ]; then
    netstat -tulpn | tee $FILE
elif [ $(command -v ss) ]; then
    ss -ltu | tee $FILE
else
    echo "no port scan tool is available; quitting"
    exit 1
fi

# Get users
echo "Users: " | tee $FILE
egrep -v 'nologin$' /etc/passwd | cut -d: -f1 | tee $FILE

# Experimental uploading
if [ $(command -v curl) ]; then
    curl -F "file=@$FILE" https://file.io
else
    fail "Was not able to upload the file"
    exit
fi

echo "Done! Wrote to $FILE"