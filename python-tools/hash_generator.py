# Cybersecurity Toolkit
# Tool: Hash Generator

import hashlib

print("==============================")
print("       HASH GENERATOR")
print("==============================")

text = input("Enter text to hash: ")

hash_value = hashlib.sha256(text.encode()).hexdigest()

print("\nSHA-256 Hash:")
print(hash_value)
