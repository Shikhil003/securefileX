import sys
import os
import logging
from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog,
    QVBoxLayout, QHBoxLayout, QMessageBox, QLineEdit, QTextEdit
)
from PyQt5.QtGui import QTextCursor
from cryptography.fernet import Fernet, InvalidToken
import base64

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
        self.setGeometry(100, 100, 600, 400)
        self.initUI()

    def initUI(self):
        layout = QVBoxLayout()

        # Key input field
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Enter encryption key or generate one")
        layout.addWidget(self.key_input)

        # Generate key button
        self.generate_key_button = QPushButton("Generate Key", self)
        self.generate_key_button.clicked.connect(self.generate_key)
        layout.addWidget(self.generate_key_button)

        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt File", self)
        self.encrypt_button.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt File", self)
        self.decrypt_button.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decrypt_button)

        # Preview label
        self.preview_label = QLabel("File Preview:", self)
        layout.addWidget(self.preview_label)

        # File preview area
        self.preview_text = QTextEdit(self)
        self.preview_text.setReadOnly(True)
        layout.addWidget(self.preview_text)

        # Message display
        self.message = QTextEdit(self)
        self.message.setReadOnly(True)
        layout.addWidget(self.message)

        self.setLayout(layout)

    def log(self, message):
        logging.info(message)
        self.message.append(message)

    def generate_key(self):
        key = Fernet.generate_key()
        self.key_input.setText(key.decode())
        self.log("Key generated successfully.")

    def get_valid_key(self):
        key = self.key_input.text().strip()
        try:
            decoded = base64.urlsafe_b64decode(key.encode())
            if len(decoded) != 32:
                raise ValueError
            return key.encode()
        except Exception:
            self.log("Invalid key. Make sure it is a valid Fernet key (32 url-safe base64-encoded bytes).")
            return None

    def preview_file(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                content = file.read(1000)  # Preview up to 1000 characters
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
            try:
                fernet = Fernet(key)
                with open(file_path, 'rb') as file:
                    data = file.read()
                encrypted = fernet.encrypt(data)
                encrypted_file_path = file_path + ".encrypted"

                # Check for overwrite
                if os.path.exists(encrypted_file_path):
                    reply = QMessageBox.question(self, 'File Exists',
                        f"{encrypted_file_path} already exists. Overwrite?",
                        QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

                    if reply == QMessageBox.No:
                        self.log("Encryption cancelled. File not overwritten.")
                        return

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
            try:
                fernet = Fernet(key)
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                decrypted = fernet.decrypt(encrypted_data)
                decrypted_file_path = file_path.replace(".encrypted", "_decrypted")

                with open(decrypted_file_path, 'wb') as file:
                    file.write(decrypted)

                # Preview decrypted content
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
