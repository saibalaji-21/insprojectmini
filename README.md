# Secure Flask Cryptography Web App

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-2.3.x-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

A secure web application implementing **AES-128-EAX encryption**, **DSA digital signatures**, and **PBKDF2 password hashing** for data confidentiality, integrity, and authentication.

## 🔐 Features

- **User Authentication**
  - Secure password storage with PBKDF2-HMAC-SHA256
  - Session management with cryptographically random secrets
- **Cryptographic Operations**
  - AES-128-EAX authenticated encryption/decryption
  - DSA (FIPS 186-3) digital signatures with SHA-256
  - Tamper detection for messages
- **Audit Logging**
  - JSON-based operation tracking
  - Timestamped user activities

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- Pip package manager

### Installation
```bash
# Clone the repository
git clone https://github.com/your-username/your-repo.git
cd your-repo

# Install dependencies
pip install -r requirements.txt
