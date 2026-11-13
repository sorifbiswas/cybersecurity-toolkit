#!/bin/bash

# Cybersecurity Toolkit
# Tool: System Information

echo "================================"
echo "       SYSTEM INFORMATION"
echo "================================"

echo "Username: $(whoami)"
echo "Hostname: $(hostname)"
echo "Operating System:"
cat /etc/os-release | grep PRETTY_NAME

echo "Kernel Version:"
uname -r

echo "Current Date:"
date

echo "================================"
