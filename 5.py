import sys
import os
import logging
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QLineEdit, QTextEdit, QComboBox
)
from PyQt5.QtGui import QTextCursor, QFont
from PyQt5.QtCore import Qt
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import base64
import os

# Setup logger
logging.basicConfig(
    filename='securefilex.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class SecureFileXGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureFileX")
        self.setGeometry(100, 100, 600, 500)
        self.initUI()
        self.apply_styles()

    def initUI(self):
        layout = QVBoxLayout()

        self.algo_box = QComboBox(self)
        self.algo_box.addItems(["Fernet (AES)", "ChaCha20", "RSA"])
        layout.addWidget(QLabel("Select Encryption Algorithm:"))
        layout.addWidget(self.algo_box)

        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Enter encryption key or generate one")
        layout.addWidget(self.key_input)

        self.generate_key_button = QPushButton("Generate Key", self)
        self.generate_key_button.clicked.connect(self.generate_key)
        layout.addWidget(self.generate_key_button)

        self.encrypt_button = QPushButton("Encrypt File", self)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        self.decrypt_button = QPushButton("Decrypt File", self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        self.preview_label = QLabel("File Preview:", self)
        layout.addWidget(self.preview_label)

        self.preview_text = QTextEdit(self)
        self.preview_text.setReadOnly(True)
        layout.addWidget(self.preview_text)

        self.message = QTextEdit(self)
        self.message.setReadOnly(True)
        layout.addWidget(self.message)

        self.setLayout(layout)

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #121212;
                color: #f0f0f0;
                font-family: 'Segoe UI', sans-serif;
                font-size: 14px;
            }
            QLineEdit, QTextEdit, QComboBox {
                background-color: #1e1e1e;
                color: #ffffff;
                border: 1px solid #333333;
                border-radius: 6px;
                padding: 5px;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                border: none;
                padding: 8px;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #005a9e;
            }
            QLabel {
                font-weight: bold;
                margin-top: 8px;
            }
        """)

    def log(self, message):
        logging.info(message)
        self.message.append(message)

    def generate_key(self):
        algo = self.algo_box.currentText()
        if algo == "Fernet (AES)":
            key = Fernet.generate_key()
            self.key_input.setText(key.decode())
            self.log("Fernet key generated successfully.")
        elif algo == "ChaCha20":
            key = os.urandom(32)
            self.key_input.setText(base64.urlsafe_b64encode(key).decode())
            self.log("ChaCha20 key generated successfully.")
        elif algo == "RSA":
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            self.key_input.setText(pem.decode())
            self.log("RSA private key generated successfully.")

    def get_valid_key(self):
        return self.key_input.text().strip()

    def preview_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read(1000)
                self.preview_text.setPlainText(content)
                self.log("File preview loaded.")
        except Exception as e:
            self.preview_text.setPlainText("")
            self.log(f"Could not preview file: {e}")

    def encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        if file_path:
            self.preview_file(file_path)
            key = self.get_valid_key()
            if not key:
                return
            algo = self.algo_box.currentText()
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()

                if algo == "Fernet (AES)":
                    fernet = Fernet(key.encode())
                    encrypted = fernet.encrypt(data)

                elif algo == "ChaCha20":
                    key_bytes = base64.urlsafe_b64decode(key.encode())
                    nonce = os.urandom(16)
                    algorithm = algorithms.ChaCha20(key_bytes, nonce)
                    cipher = Cipher(algorithm, mode=None, backend=default_backend())
                    encryptor = cipher.encryptor()
                    encrypted = nonce + encryptor.update(data)

                elif algo == "RSA":
                    private_key = serialization.load_pem_private_key(
                        key.encode(), password=None, backend=default_backend()
                    )
                    public_key = private_key.public_key()
                    encrypted = public_key.encrypt(
                        data,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )

                encrypted_file_path = file_path + ".encrypted"

                with open(encrypted_file_path, 'wb') as file:
                    file.write(encrypted)

                self.log(f"File encrypted successfully: {encrypted_file_path}")

            except Exception as e:
                self.log(f"Encryption failed: {e}")

    def decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        if file_path:
            key = self.get_valid_key()
            if not key:
                return
            algo = self.algo_box.currentText()
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()

                if algo == "Fernet (AES)":
                    fernet = Fernet(key.encode())
                    decrypted = fernet.decrypt(encrypted_data)

                elif algo == "ChaCha20":
                    key_bytes = base64.urlsafe_b64decode(key.encode())
                    nonce = encrypted_data[:16]
                    ciphertext = encrypted_data[16:]
                    algorithm = algorithms.ChaCha20(key_bytes, nonce)
                    cipher = Cipher(algorithm, mode=None, backend=default_backend())
                    decryptor = cipher.decryptor()
                    decrypted = decryptor.update(ciphertext)

                elif algo == "RSA":
                    private_key = serialization.load_pem_private_key(
                        key.encode(), password=None, backend=default_backend()
                    )
                    decrypted = private_key.decrypt(
                        encrypted_data,
                        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )

                decrypted_file_path = file_path.replace(".encrypted", "_decrypted")

                with open(decrypted_file_path, 'wb') as file:
                    file.write(decrypted)

                self.preview_file(decrypted_file_path)

                self.log(f"File decrypted successfully: {decrypted_file_path}")
            except InvalidToken:
                self.log("Decryption failed: Invalid key or corrupted file.")
            except Exception as e:
                self.log(f"Decryption failed: {e}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    gui = SecureFileXGUI()
    gui.show()
    sys.exit(app.exec_())
