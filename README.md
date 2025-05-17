# Password Strength and Pwned Password Checker

## What is this?

A simple Windows console program written in C++ that:

- Checks how strong your password is (based on length, uppercase, lowercase, digits, special characters).
- Checks if your password has appeared in any known data breaches using the Have I Been Pwned API.

## How does it work?

1. It creates a SHA-1 hash of your password.
2. Sends the first 5 characters of this hash to the Have I Been Pwned API.
3. Checks if the rest of the hash appears in the API response.
4. Tells you if your password is weak, moderate, strong, or if it has been compromised.

## Requirements

- Windows OS
- g++ compiler with OpenSSL installed
- WinINet library (comes with Windows)

## How to compile

```bash
g++ main.cpp -o PassAlyzer -lwininet -lssl -lcrypto
