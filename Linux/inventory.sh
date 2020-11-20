#!/usr/bin/env bash

# red
fail () {
    echo "$(tput setaf 1)[FAIL] $1$(tput sgr0)"
}

# green
pass () {
    echo "$(tput setaf 2)[PASS] $1$(tput sgr0)"
}

# yellow
warning () {
    echo "$(tput setaf 3)[WARNING] $1$(tput sgr0)"
}

# white
info () {
    echo "$(tput setaf 7)[INFO] $1$(tput sgr0)"
}

FILE="inventory.txt"

info "Starting scan..."

# Get hostname
info "Getting hostname"
echo "hostname: $(hostname)" > $FILE
echo >> $FILE
pass "Finished getting hostname"

# Get OS info
if [ $(command -v hostnamectl) ]; then
    info "Using hostnamectl to get OS info"
    hostnamectl >> $FILE
elif [ -e /etc/os-release ]; then
    info "Using /etc/os-release"
    cat /etc/os-release >> $FILE
elif [ -e /etc/lsb-release ]; then
    info "Using /etc/lsb-release"
    cat /etc/lsb-release >> $FILE
else
    fail "Was not able to get OS info"
    exit 1
fi
pass "Finished getting OS info"
echo >> $FILE

# Get IP information
if [ $(command -v ip) ]; then
    info "Using ip to get ip info"
    ip -brief address >> $FILE
elif [ $(command -v ifconfig) ]; then
    warning "ip is not installed, using ifconfig"
    ifconfig >> $FILE
else
    fail "Neither ip nor ifconfig are installed; quitting."
    exit 1
fi
pass "Finished getting IP info"
echo >> $FILE

# Get open ports
if [ $(command -v nmap) ]; then
    info "Using nmap to look at open ports"
    nmap -sV localhost >> $FILE
elif [ $(command -v netstat) ]; then
    warning "nmap is not installed. Using netstat"
    netstat -tulpn >> $FILE
elif [ $(command -v ss) ]; then
    warning "nmap and netstat are not installed. Using ss"
    ss -ltu >> $FILE
else
    fail "no port scan tool is available; quitting"
    exit 1
fi
pass "Finished port scan"
echo >> $FILE

# Get users
echo "Users: " >> $FILE
egrep -v 'nologin$' /etc/passwd | cut -d: -f1 >> $FILE
