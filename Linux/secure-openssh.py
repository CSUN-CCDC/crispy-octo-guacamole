#!/usr/bin/env python3
import os

# Colorful functions for printing (Maybe move to another file)
def warning(text):
    print(f"\033[93m[ WARNING ]: {text}\033[0m")

def failed(text):
    print(f"\033[91m[ FAIL ]: {text}\033[0m")

def passed(text):
    print(f"\033[92m[ PASS ]: {text}\033[0m")


for line in open("/etc/ssh/sshd_config", 'r'):
    if line == '\n' or line.startswith('#'):
        continue
    option = line.split()[0]
    value = ' '.join(line.split()[1:])
    if option == "PermitRootLogin":
        # Enabled root login is bad
        if value == "no" or value == "prohibit-password":
            passed("Root login is disabled")
        elif value == "yes":
            failed("Root login is enabled.")
    elif option == "LogLevel":
        # Any log level is okay; quiet is not
        if value == "QUIET":
            failed("There is no logging enabled")
    elif option == "X11Forwarding":
        # X11 bad
        if value != "no":
            failed("X11 forwarding is not disabled")
        
