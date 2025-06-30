from tkinter import *
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from PIL import Image, ImageTk
import os

class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Simple Encryption Tool")
        self.root.attributes("-fullscreen", True)
        self.root.bind("<Escape>", lambda e: self.root.attributes("-fullscreen", False))

        # Background image
        self.set_background("background.jpg")

        # Generate or load key
        self.key = self.load_or_generate_key()
        self.cipher = Fernet(self.key)

        # UI elements
        self.create_widgets()

    def set_background(self, image_path):
        self.bg_image = Image.open("sk.jpg")
        self.bg_photo = ImageTk.PhotoImage(self.bg_image.resize((self.root.winfo_screenwidth(), self.root.winfo_screenheight())))
        self.background_label = Label(self.root, image=self.bg_photo)
        self.background_label.place(x=0, y=0, relwidth=1, relheight=1)

    def load_or_generate_key(self):
        try:
            with open('secret.key', 'rb') as key_file:
                return key_file.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open('secret.key', 'wb') as key_file:
                key_file.write(key)
            return key

    def create_widgets(self):
        # Container Frame on top of background
        self.container = Frame(self.root, bg="#ffffff", bd=2)
        self.container.place(relx=0.5, rely=0.5, anchor=CENTER, relwidth=0.8, relheight=0.85)

        self.notebook = ttk.Notebook(self.container)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)

        # Text Encryption Tab
        self.text_frame = Frame(self.notebook, bg="#e6f2ff")
        self.notebook.add(self.text_frame, text="Text Encryption")
        self.setup_text_tab()

        # File Encryption Tab
        self.file_frame = Frame(self.notebook, bg="#e6ffe6")
        self.notebook.add(self.file_frame, text="File Encryption")
        self.setup_file_tab()

        # Key Label & Save Button
        self.key_label = Label(self.container, text=f"Key: {self.key.decode()[:20]}...", bg="#ffffff", fg="black", font=("Arial", 10))
        self.key_label.pack(pady=5)

        Button(self.container, text="Save Key To File", command=self.save_key, bg="#0066cc", fg="white").pack(pady=5)

    def setup_text_tab(self):
        Label(self.text_frame, text="Enter Text:", bg="#e6f2ff").pack(pady=5)
        self.text_input = Text(self.text_frame, height=6)
        self.text_input.pack(fill=BOTH, expand=True, padx=10, pady=5)

        Button(self.text_frame, text="Encrypt Text", command=self.encrypt_text, bg="#3399ff", fg="white").pack(pady=5)
        Button(self.text_frame, text="Decrypt Text", command=self.decrypt_text, bg="#339933", fg="white").pack(pady=5)

        Label(self.text_frame, text="Result:", bg="#e6f2ff").pack(pady=5)
        self.text_result = Text(self.text_frame, height=6)
        self.text_result.pack(fill=BOTH, expand=True, padx=10, pady=5)

    def setup_file_tab(self):
        Button(self.file_frame, text="Select File", command=self.select_file, bg="#3399ff", fg="white").pack(pady=10)
        self.file_label = Label(self.file_frame, text="No file selected", bg="#e6ffe6")
        self.file_label.pack(pady=5)

        Button(self.file_frame, text="Encrypt File", command=self.encrypt_file, bg="#ff9933", fg="white").pack(pady=5)
        Button(self.file_frame, text="Decrypt File", command=self.decrypt_file, bg="#ff3300", fg="white").pack(pady=5)

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))

    def encrypt_text(self):
        text = self.text_input.get("1.0", END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to encrypt")
            return
        try:
            encrypted = self.cipher.encrypt(text.encode())
            self.text_result.delete("1.0", END)
            self.text_result.insert("1.0", encrypted.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_text(self):
        text = self.text_input.get("1.0", END).strip()
        if not text:
            messagebox.showerror("Error", "Please enter text to decrypt")
            return
        try:
            decrypted = self.cipher.decrypt(text.encode())
            self.text_result.delete("1.0", END)
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
    root = Tk()
    app = EncryptionApp(root)
    root.mainloop()
