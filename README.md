# RSA Encrypted Client-Server Communication

A secure client-server communication system implementing RSA encryption and SHA256 hashing for message integrity verification. This project demonstrates cryptographic principles including public-key encryption, digital signatures, and secure key exchange protocols.

## 📋 Project Overview

This project implements a secure communication channel between a client and server using:
- **RSA-1024 encryption** for secure message transmission
- **SHA256 hashing** for message integrity verification
- **Dual-socket architecture** (control and data channels)
- **PKCS1_OAEP padding** for enhanced security

## 🔐 Security Features

- **Public Key Exchange**: Secure tunnel establishment through RSA keypair exchange
- **Message Encryption**: All messages encrypted with recipient's public key
- **Integrity Verification**: SHA256 hash comparison to detect tampering
- **Secure Protocol**: Multi-step handshake ensuring authenticated communication

## 🚀 Installation

### Prerequisites
- Python 3.7+
- pycryptodome library

## 🔗 Links

- **GitHub Repository**: [https://github.com/catacisneros/cryptography](https://github.com/catacisneros/cryptography)
- **Demo Video**: [YouTube Demo](https://www.youtube.com/watch?v=_WXbKPG8QiM&t=6s)
