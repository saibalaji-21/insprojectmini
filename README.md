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

```sh
python --version
```

## 🔧 Installation and Setup
**Step 1:** Clone the Repository

```sh
git clone <your-repo-url>
cd <your-project-folder>
```
**Step 2:** Create and Activate a Virtual Environment
For Windows:

```sh
python -m venv venv
venv\Scripts\activate
```
For macOS/Linux:

```sh
python3 -m venv venv
source venv/bin/activate
```
## 🎯 Running the Application
Once the setup is complete, start the Flask application by running:

```sh
python app.py
```
The server will start at https://localhost:5000

---

[Watch the Demo](https://youtu.be/L3l6fcQ2NHM?feature=shared)]



