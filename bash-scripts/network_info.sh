#!/bin/bash

# Cybersecurity Toolkit
# Tool: Network Information

echo "================================"
echo "       NETWORK INFORMATION"
echo "================================"

echo "IP Address:"
hostname -I

echo ""
echo "Network Interfaces:"
ip -brief address

echo ""
echo "Routing Table:"
ip route

echo "================================"
