# Cybersecurity Toolkit
# Tool: IP Address Validator

import ipaddress

print("==============================")
print("     IP ADDRESS VALIDATOR")
print("==============================")

ip = input("Enter an IP address: ")

try:
    address = ipaddress.ip_address(ip)
    print("[+] Valid IP Address")
    print("IP Version:", address.version)

except ValueError:
    print("[-] Invalid IP Address")
