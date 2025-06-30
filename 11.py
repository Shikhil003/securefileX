import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from PIL import Image
import os

# Set appearance and theme
ctk.set_appearance_mode("Dark")  # Options: "Dark", "Light", "System"
ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Modern Encryption Tool")
        self.root.geometry("1200x700")

        # Generate or load key
        self.key = self.load_or_generate_key()
        self.cipher = Fernet(self.key)

        # Main layout
        self.create_layout()

    def load_or_generate_key(self):
        try:
            with open('secret.key', 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open('secret.key', 'wb') as key_file:
                key_file.write(key)
            return key

    def create_layout(self):
        # Tab view
        self.tabview = ctk.CTkTabview(self.root, width=1000, height=600)
        self.tabview.pack(pady=20)

        self.text_tab = self.tabview.add("Text Encryption")
        self.file_tab = self.tabview.add("File Encryption")

        self.setup_text_tab()
        self.setup_file_tab()

        # Key display and save
        ctk.CTkLabel(self.root, text=f"Key: {self.key.decode()[:20]}...", font=ctk.CTkFont(size=12)).pack(pady=10)
        ctk.CTkButton(self.root, text="Save Key To File", command=self.save_key).pack()

    def setup_text_tab(self):
        ctk.CTkLabel(self.text_tab, text="Enter Text:", anchor="w").pack(pady=5, fill="x", padx=10)

        self.text_input = ctk.CTkTextbox(self.text_tab, height=120)
        self.text_input.pack(padx=10, pady=5, fill="both", expand=True)

        ctk.CTkButton(self.text_tab, text="Encrypt Text", command=self.encrypt_text).pack(pady=5)
        ctk.CTkButton(self.text_tab, text="Decrypt Text", command=self.decrypt_text).pack(pady=5)

        ctk.CTkLabel(self.text_tab, text="Result:", anchor="w").pack(pady=5, fill="x", padx=10)

        self.text_result = ctk.CTkTextbox(self.text_tab, height=120)
        self.text_result.pack(padx=10, pady=5, fill="both", expand=True)

    def setup_file_tab(self):
        ctk.CTkButton(self.file_tab, text="Select File", command=self.select_file).pack(pady=10)

        self.file_label = ctk.CTkLabel(self.file_tab, text="No file selected", text_color="gray")
        self.file_label.pack(pady=5)

        ctk.CTkButton(self.file_tab, text="Encrypt File", command=self.encrypt_file).pack(pady=5)
        ctk.CTkButton(self.file_tab, text="Decrypt File", command=self.decrypt_file).pack(pady=5)

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_label.configure(text=os.path.basename(self.file_path), text_color="white")

    def encrypt_text(self):
        text = self.text_input.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        try:
            encrypted = self.cipher.encrypt(text.encode())
            self.text_result.delete("1.0", "end")
            self.text_result.insert("1.0", encrypted.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_text(self):
        text = self.text_input.get("1.0", "end").strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to decrypt")
            return
        try:
            decrypted = self.cipher.decrypt(text.encode())
            self.text_result.delete("1.0", "end")
            self.text_result.insert("1.0", decrypted.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def encrypt_file(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Error", "Please select a file first")
            return
        try:
            with open(self.file_path, 'rb') as file:
                file_data = file.read()
            encrypted_data = self.cipher.encrypt(file_data)

            save_path = filedialog.asksaveasfilename(
                initialfile=os.path.basename(self.file_path) + ".encrypted",
                defaultextension=".encrypted"
            )
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(encrypted_data)
                messagebox.showinfo("Success", "File encrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"File encryption failed: {str(e)}")

    def decrypt_file(self):
        if not hasattr(self, 'file_path'):
            messagebox.showerror("Error", "Please select a file first")
            return
        try:
            with open(self.file_path, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = self.cipher.decrypt(encrypted_data)

            save_path = filedialog.asksaveasfilename(
                initialfile=os.path.basename(self.file_path).replace(".encrypted", ""),
                defaultextension=""
            )
            if save_path:
                with open(save_path, 'wb') as file:
                    file.write(decrypted_data)
                messagebox.showinfo("Success", "File decrypted successfully")
        except Exception as e:
            messagebox.showerror("Error", f"File decryption failed: {str(e)}")

    def save_key(self):
        save_path = filedialog.asksaveasfilename(
            initialfile="secret.key",
            defaultextension=".key"
        )
        if save_path:
            try:
                with open(save_path, 'wb') as file:
                    file.write(self.key)
                messagebox.showinfo("Success", "Key saved successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save key: {str(e)}")


if __name__ == "__main__":
    root = ctk.CTk()
    app = EncryptionApp(root)
    root.mainloop()
