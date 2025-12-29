# ZENITH PROTOCOL (Horizon Edition)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Encryption](https://img.shields.io/badge/Encryption-AES--GCM%20%7C%20RSA--4096-green)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)

**Zenith Protocol** is an advanced cryptographic tool designed for secure communication, data concealment (Steganography), and anti-forensic operations. Built with a modern GUI using `customtkinter`, it offers military-grade encryption accessible from a sleek dashboard.

## 🛡️ Key Features

- **Asymmetric Identity:** Generates RSA-4096 Keypairs (Private/Public) protected by a passphrase.
- **Secure Vault:** Encrypts any file type using **AES-256-GCM** (Data) + **RSA-OAEP** (Keys).
- **Phantom Steganography:** Hides encrypted data inside PNG images using LSB manipulation.
- **Anti-Forensics:**
  - **Timestomping:** Resets file modification dates to 2010 to confuse forensic timeline analysis.
  - **File Shredding:** Securely wipes original files (overwrite with random bytes) after encryption.
- **Tamper Proof:** Verifies data integrity with SHA-256 hashing. If 1 bit is changed, decryption is rejected.
- **Modern GUI:** A futuristic, dark-themed interface for ease of use.

## ⚙️ Installation

### Prerequisites
- Python 3.10 or higher.
- Linux/WSL (Recommended) or Windows.

### 1. Clone the Repository
```bash
git clone https://github.com/Shadownet43/Zenith-Protocol.git
cd Zenith-Protocol

```

### 2. System Dependencies (Linux/WSL Only)

If you are running this on Ubuntu/WSL, you must install the Tkinter bridge:

```bash
sudo apt update
sudo apt install python3-tk -y

```

*(Windows users typically have this pre-installed with Python)*

### 3. Install Python Libraries

It is recommended to use a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt

```

## 🚀 Usage

Run the GUI application:

```bash
python3 zenith_gui.py

```

### Operation Modules:

1. **Create Identity:** Generate your `.pem` keys. **Keep your Private Key safe!**
2. **Secure Vault:** Select a file and a recipient's Public Key to encrypt.
3. **Stego Inject:** Hide the encrypted `.zenith` file into a dummy PNG image.
4. **Stego Extract:** Recover the hidden data from a PNG image.
5. **Restore Data:** Decrypt the file using your Private Key and Passphrase.

## ⚠️ Disclaimer

This tool is created for **educational purposes and privacy protection**. The developer is not responsible for any misuse of this software for illegal activities.

---

**Created by Shadownet43** | *The Serpent Protocol v4.0*

```
