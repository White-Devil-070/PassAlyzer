# 🔐 Password Strength and Local Breach Checker (C++ - Offline Version)

This is a simple C++ console application that allows users to:
- ✅ **Check password strength** based on its composition and length
- ✅ **Detect if a password has been leaked** using a local plain-text file (`pwnedpasswords.txt`) containing known breached passwords

This version does **not require internet access** and works entirely **offline**.

---

## 📁 Project Structure

/PassAlyzer
│
├── main.cpp # The main C++ source code

├── pwnedpasswords.txt # Local breach password list (plain text)

└── README.md # This documentation file

---

## ⚙️ Features

### 🧠 Password Strength Checker

Analyzes the password based on:
- Presence of **uppercase** letters
- Presence of **lowercase** letters
- Presence of **digits**
- Presence of **special characters**
- Length of password (minimum 8 characters)

🔍 Output messages include:
- `Too Weak`, `Very Weak`, `Weak`, `Moderate`, and `Strong`

---

### 🛡️ Local Breach Detection

- Loads a list of breached passwords from `pwnedpasswords.txt`
- Compares the input password directly (not hashed)
- Warns user if the password appears in the local breach list

---

## 🚀 How to Compile & Run

### 1. Prepare the Files

Ensure you have:
- `main.cpp`
- `pwnedpasswords.txt` in the **same folder**

Example `pwnedpasswords.txt` content:
123456
password
qwerty
letmein
iloveyou

### 2. Compile and Run (Using g++)

```bash
g++ main.cpp -o PassAlyzer

```
Run .exe file created in the current directory.
### 3. Sample Usage

Enter the password to check strength: password
Password Strength: Very Weak (Only lowercase letters)
WARNING: This password has been found in a local breach database!

