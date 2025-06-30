import os
import json
import hashlib
import threading
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from PyQt5.QtWidgets import QApplication, QFileDialog, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QLineEdit, QLabel, QComboBox
from PyQt5.QtGui import QIcon

class SecureFileX:
    def __init__(self, master_password: str):
        self.master_key = PBKDF2(master_password.encode(), b'salt', dkLen=32)
        self.db_file = "secure_db.enc"
        self.rsa_key = None  # Placeholder for RSA keys

    def generate_rsa_keys(self):
        """Generate RSA public/private key pair."""
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open("private.pem", "wb") as priv_file:
            priv_file.write(private_key)
        with open("public.pem", "wb") as pub_file:
            pub_file.write(public_key)
        self.rsa_key = key
        return private_key, public_key

    def encrypt(self, file_path: str, password: str, algorithm: str):
        """Encrypt a file using AES, RSA, or ChaCha20."""
        key = PBKDF2(password.encode(), b'salt', dkLen=32)

        if algorithm == "AES":
            cipher = AES.new(key, AES.MODE_GCM)
            nonce = cipher.nonce
            with open(file_path, "rb") as f:
                data = f.read()
                ciphertext, tag = cipher.encrypt_and_digest(data)
            enc_data = nonce + tag + ciphertext

        elif algorithm == "ChaCha20":
            cipher = ChaCha20.new(key=key)
            nonce = cipher.nonce
            with open(file_path, "rb") as f:
                data = f.read()
                ciphertext = cipher.encrypt(data)
            enc_data = nonce + ciphertext

        elif algorithm == "RSA":
            if not self.rsa_key:
                self.generate_rsa_keys()
            with open("public.pem", "rb") as pub_file:
                public_key = RSA.import_key(pub_file.read())
            cipher = PKCS1_OAEP.new(public_key)
            with open(file_path, "rb") as f:
                data = f.read()
                enc_data = cipher.encrypt(data)

        else:
            raise ValueError("Unsupported encryption algorithm!")

        enc_file_path = file_path + f".{algorithm}.enc"
        with open(enc_file_path, "wb") as ef:
            ef.write(enc_data)

        return enc_file_path

    def decrypt(self, enc_file_path: str, password: str, algorithm: str):
        """Decrypt a file using AES, RSA, or ChaCha20."""
        key = PBKDF2(password.encode(), b'salt', dkLen=32)

        with open(enc_file_path, "rb") as f:
            file_data = f.read()

        if algorithm == "AES":
            nonce, tag, ciphertext = file_data[:16], file_data[16:32], file_data[32:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        elif algorithm == "ChaCha20":
            nonce, ciphertext = file_data[:8], file_data[8:]
            cipher = ChaCha20.new(key=key, nonce=nonce)
            decrypted_data = cipher.decrypt(ciphertext)

        elif algorithm == "RSA":
            if not self.rsa_key:
                with open("private.pem", "rb") as priv_file:
                    self.rsa_key = RSA.import_key(priv_file.read())
            cipher = PKCS1_OAEP.new(self.rsa_key)
            decrypted_data = cipher.decrypt(file_data)

        else:
            raise ValueError("Unsupported decryption algorithm!")

        dec_file_path = enc_file_path.replace(f".{algorithm}.enc", "")
        with open(dec_file_path, "wb") as df:
            df.write(decrypted_data)

        return dec_file_path


# GUI Integration
class SecureFileXGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SecureFileX")
        self.setWindowIcon(QIcon('icon.png'))
        self.initUI()

    def initUI(self):
        self.layout = QVBoxLayout()
        
        self.password_label = QLabel("Enter Password:")
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)

        self.algorithm_label = QLabel("Select Encryption Algorithm:")
        self.algorithm_dropdown = QComboBox()
        self.algorithm_dropdown.addItems(["AES", "RSA", "ChaCha20"])

        self.encrypt_button = QPushButton("Encrypt File")
        self.decrypt_button = QPushButton("Decrypt File")
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        
        self.encrypt_button.clicked.connect(self.encrypt_file)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        
        self.layout.addWidget(self.password_label)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.algorithm_label)
        self.layout.addWidget(self.algorithm_dropdown)
        self.layout.addWidget(self.encrypt_button)
        self.layout.addWidget(self.decrypt_button)
        self.layout.addWidget(self.log_output)
        
        container = QWidget()
        container.setLayout(self.layout)
        self.setCentralWidget(container)

    def log(self, message):
        self.log_output.append(message)

    def encrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Encrypt")
        password = self.password_input.text()
        algorithm = self.algorithm_dropdown.currentText()

        if file_path and password:
            secure = SecureFileX(password)
            enc_path = secure.encrypt(file_path, password, algorithm)
            self.log(f"Encrypted: {enc_path}")

    def decrypt_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Decrypt")
        password = self.password_input.text()
        algorithm = self.algorithm_dropdown.currentText()

        if file_path and password:
            secure = SecureFileX(password)
            try:
                dec_path = secure.decrypt(file_path, password, algorithm)
                self.log(f"Decrypted: {dec_path}")
            except ValueError:
                self.log("Decryption failed: Incorrect password or tampered file.")


if __name__ == "__main__":
    app = QApplication([])
    gui = SecureFileXGUI()
    gui.show()
    app.exec_()
