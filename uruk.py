import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from cryptography.fernet import Fernet

# Notes:
# Password is encrypted with Fernet and stored in password.enc with key in key.key.
# Removed Folder Compression Section to simplify and ensure cross-platform compatibility.

class PasswordManager:
    def __init__(self):
        self.password_file = "password.enc"
        self.key_file = "key.key"
        self.fernet = None
        self.load_or_generate_key()

    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, "rb") as key_file:
                key = key_file.read()
            self.fernet = Fernet(key)
        else:
            key = Fernet.generate_key()
            self.fernet = Fernet(key)
            with open(self.key_file, "wb") as key_file:
                key_file.write(key)

    def encrypt_password(self, password):
        return self.fernet.encrypt(password.encode())

    def decrypt_password(self, encrypted_password):
        return self.fernet.decrypt(encrypted_password).decode()

    def save_password(self, password):
        encrypted_password = self.encrypt_password(password)
        with open(self.password_file, "wb") as pw_file:
            pw_file.write(encrypted_password)

    def get_password(self):
        if os.path.exists(self.password_file):
            with open(self.password_file, "rb") as pw_file:
                encrypted_password = pw_file.read()
            return self.decrypt_password(encrypted_password)
        return None

class LoginWindow:
    def __init__(self, root, password_manager):
        self.root = root
        self.password_manager = password_manager
        # Check if password exists; if not, trigger initial setup
        if not self.password_manager.get_password():
            self.setup_initial_password()
        else:
            self.setup_login_window()

    def setup_login_window(self):
        self.root.title("Login")
        self.root.geometry("300x200")
        self.root.resizable(False, False)

        tk.Label(self.root, text="Enter Password", font=("Arial", 14)).pack(pady=20)
        self.password_entry = tk.Entry(self.root, show="*")
        self.password_entry.pack(pady=10)

        tk.Button(self.root, text="Login", command=self.check_password).pack(pady=5)
        tk.Button(self.root, text="Change Password", command=self.change_password).pack(pady=5)

    def check_password(self):
        entered_password = self.password_entry.get()
        stored_password = self.password_manager.get_password()
        if stored_password and entered_password == stored_password:
            self.root.destroy()
            self.open_main_app()
        else:
            messagebox.showerror("Error", "Incorrect password. Try again or change password.")
            self.password_entry.delete(0, tk.END)

    def setup_initial_password(self):
        self.root.title("Set Initial Password")
        self.root.geometry("300x200")
        self.root.resizable(False, False)

        tk.Label(self.root, text="Set Initial Password", font=("Arial", 14)).pack(pady=20)
        password_var = tk.StringVar()
        tk.Entry(self.root, textvariable=password_var, show="*").pack(pady=10)
        tk.Button(self.root, text="Set Password", command=lambda: self.save_initial_password(self.root, password_var.get())).pack(pady=5)

    def save_initial_password(self, window, password):
        if len(password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")
            return
        self.password_manager.save_password(password)
        window.destroy()
        self.open_login_window()

    def change_password(self):
        old_password = self.password_entry.get()
        stored_password = self.password_manager.get_password()
        if stored_password and old_password == stored_password:
            self.root.destroy()
            change_window = tk.Tk()
            change_window.title("Change Password")
            change_window.geometry("300x250")
            change_window.resizable(False, False)

            tk.Label(change_window, text="Change Password", font=("Arial", 14)).pack(pady=20)
            new_password_var = tk.StringVar()
            confirm_password_var = tk.StringVar()
            tk.Label(change_window, text="New Password:").pack()
            tk.Entry(change_window, textvariable=new_password_var, show="*").pack(pady=5)
            tk.Label(change_window, text="Confirm Password:").pack()
            tk.Entry(change_window, textvariable=confirm_password_var, show="*").pack(pady=5)
            tk.Button(change_window, text="Save", command=lambda: self.update_password(change_window, new_password_var.get(), confirm_password_var.get())).pack(pady=10)
        else:
            messagebox.showerror("Error", "Incorrect old password.")

    def update_password(self, window, new_password, confirm_password):
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if len(new_password) < 8:
            messagebox.showerror("Error", "Password must be at least 8 characters long.")
            return
        self.password_manager.save_password(new_password)
        window.destroy()
        self.open_login_window()

    def open_login_window(self):
        self.root = tk.Tk()
        self.setup_login_window()
        self.root.mainloop()

    def open_main_app(self):
        main_root = tk.Tk()
        app = FileCryptoApp(main_root)
        main_root.mainloop()

class FileCryptoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption & Decryption")

        # Get screen dimensions
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()

        # Set window dimensions to 80% of screen width and 60% of screen height
        window_width = int(screen_width * 0.8)
        window_height = int(screen_height * 0.6)
        self.root.geometry(f"{window_width}x{window_height}")

        # About Button (Placed at the top)
        self.about_frame = tk.Frame(self.root)
        self.about_frame.pack(pady=5)
        tk.Button(self.about_frame, text="About", command=self.show_about).pack()

        # Create a horizontal PanedWindow to split the window into two sections
        self.pane = tk.PanedWindow(root, orient=tk.HORIZONTAL, sashrelief="raised", sashwidth=5)
        self.pane.pack(fill="both", expand=True)

        # Calculate equal width for each section (window_width / 2)
        initial_section_width = window_width // 2

        # Section 1: Encryption Section (Left)
        self.encryption_frame = tk.Frame(self.pane)
        self.pane.add(self.encryption_frame, width=initial_section_width)

        tk.Label(self.encryption_frame, text="Encryption Section", font=("Arial", 14)).pack(pady=10)
        tk.Button(self.encryption_frame, text="Select File to Encrypt", command=self.select_file).pack(pady=5)
        self.file_label = tk.Label(self.encryption_frame, text="No file selected")
        self.file_label.pack()
        tk.Label(self.encryption_frame, text="AES Key Length:").pack()
        self.key_length_var = tk.StringVar(value="256")
        tk.OptionMenu(self.encryption_frame, self.key_length_var, "128", "192", "256").pack()
        tk.Button(self.encryption_frame, text="Encrypt & Sign File", command=self.encrypt_and_sign).pack(pady=5)
        tk.Button(self.encryption_frame, text="Save Encrypted File", command=self.save_encrypted_file).pack(pady=5)

        # Key Display and Save Buttons
        tk.Label(self.encryption_frame, text="Public Key (Copyable):").pack(pady=5)
        self.public_key_text = tk.Text(self.encryption_frame, height=4, width=40, state="disabled")
        self.public_key_text.pack()
        tk.Button(self.encryption_frame, text="Save Public Key", command=self.save_public_key).pack(pady=2)

        tk.Label(self.encryption_frame, text="Private Key (Copyable):").pack(pady=5)
        self.private_key_text = tk.Text(self.encryption_frame, height=4, width=40, state="disabled")
        self.private_key_text.pack()
        tk.Button(self.encryption_frame, text="Save Private Key", command=self.save_private_key).pack(pady=2)

        # AES Key Display and Save Button
        tk.Label(self.encryption_frame, text="AES Key (Copyable):").pack(pady=5)
        self.aes_key_text = tk.Text(self.encryption_frame, height=2, width=40, state="disabled")
        self.aes_key_text.pack()
        tk.Button(self.encryption_frame, text="Save AES Key", command=self.save_aes_key).pack(pady=2)

        # Section 2: Decryption Section (Right)
        self.decryption_frame = tk.Frame(self.pane)
        self.pane.add(self.decryption_frame, width=initial_section_width)

        tk.Label(self.decryption_frame, text="Decryption Section", font=("Arial", 14)).pack(pady=10)
        tk.Button(self.decryption_frame, text="Select File to Decrypt", command=self.select_file_to_decrypt).pack(pady=5)
        self.decrypt_file_label = tk.Label(self.decryption_frame, text="No file selected")
        self.decrypt_file_label.pack()
        tk.Button(self.decryption_frame, text="Decrypt File", command=self.decrypt_file).pack(pady=5)

    def show_about(self):
        # Create a custom dialog to prevent wrapping
        dialog = tk.Toplevel(self.root)
        dialog.title("About")
        dialog.geometry("400x200")
        dialog.resizable(False, False)

        # Center the dialog on the parent window
        dialog.transient(self.root)
        dialog.grab_set()

        # Add the About information with a Label
        about_info = "APP : URUK\n\nDEVELOPER : Ali Al-Kazaly aLiGeNiUs The Hackers \nVERSION : 1.0.0.0  (2025)"
        label = tk.Label(dialog, text=about_info, font=("Arial", 12), justify="center")
        label.pack(pady=20)

        # Add an OK button to close the dialog
        tk.Button(dialog, text="OK", command=dialog.destroy).pack(pady=10)

        # Center the dialog relative to the root window
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")

    def select_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.file_label.config(text=os.path.basename(self.file_path))

    def select_file_to_decrypt(self):
        self.decrypt_file_path = filedialog.askopenfilename()
        if self.decrypt_file_path:
            self.decrypt_file_label.config(text=os.path.basename(self.decrypt_file_path))

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode("utf-8")

        self.public_key_text.config(state="normal")
        self.public_key_text.delete(1.0, tk.END)
        self.public_key_text.insert(tk.END, public_pem)
        self.public_key_text.config(state="disabled")

        self.private_key_text.config(state="normal")
        self.private_key_text.delete(1.0, tk.END)
        self.private_key_text.insert(tk.END, private_pem)
        self.private_key_text.config(state="disabled")

    def encrypt_and_sign(self):
        if not self.file_path:
            messagebox.showerror("Error", "Please select a file to encrypt")
            return

        self.generate_keys()
        key_length = int(self.key_length_var.get())
        self.aes_key = os.urandom(key_length // 8)

        with open(self.file_path, "rb") as f:
            original_data = f.read()

        signature = self.private_key.sign(
            original_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_data = original_data + b"\0" * (16 - len(original_data) % 16)
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        self.encrypted_file = iv + encrypted_data + signature

        self.aes_key_text.config(state="normal")
        self.aes_key_text.delete(1.0, tk.END)
        self.aes_key_text.insert(tk.END, self.aes_key.hex())
        self.aes_key_text.config(state="disabled")
        
        messagebox.showinfo("Success", "File encrypted and signed successfully")

    def save_encrypted_file(self):
        if not self.encrypted_file:
            messagebox.showerror("Error", "No encrypted file to save")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".enc")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.encrypted_file)
            messagebox.showinfo("Success", "Encrypted file saved")

    def save_public_key(self):
        if not self.public_key:
            messagebox.showerror("Error", "No public key to save")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if save_path:
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            with open(save_path, "wb") as f:
                f.write(public_pem)
            messagebox.showinfo("Success", "Public key saved")

    def save_private_key(self):
        if not self.private_key:
            messagebox.showerror("Error", "No private key to save")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".pem", filetypes=[("PEM files", "*.pem")])
        if save_path:
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(save_path, "wb") as f:
                f.write(private_pem)
            messagebox.showinfo("Success", "Private key saved")

    def save_aes_key(self):
        if not self.aes_key:
            messagebox.showerror("Error", "No AES key to save")
            return
        save_path = filedialog.asksaveasfilename(defaultextension=".key", filetypes=[("Key files", "*.key")])
        if save_path:
            with open(save_path, "wb") as f:
                f.write(self.aes_key)
            messagebox.showinfo("Success", "AES key saved")

    def decrypt_file(self):
        if not hasattr(self, "decrypt_file_path") or not self.decrypt_file_path:
            messagebox.showerror("Error", "Please select a file to decrypt")
            return

        private_key_path = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        if not private_key_path:
            return

        with open(private_key_path, "rb") as key_file:
            private_key = serialization.load_pem_private_key(key_file.read(), password=None)
            public_key = private_key.public_key()

        with open(self.decrypt_file_path, "rb") as f:
            encrypted_data = f.read()

        iv = encrypted_data[:16]
        remaining_data = encrypted_data[16:]
        signature_length = 256
        signature = remaining_data[-signature_length:]
        encrypted_payload = remaining_data[:-signature_length]

        aes_key_path = filedialog.askopenfilename(title="Select AES Key", filetypes=[("Key files", "*.key")])
        if not aes_key_path:
            return

        with open(aes_key_path, "rb") as key_file:
            aes_key = key_file.read()

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(encrypted_payload) + decryptor.finalize()
        decrypted_data = decrypted_padded.rstrip(b"\0")

        if not self.file_path or not os.path.exists(self.file_path):
            self.file_path = filedialog.askopenfilename(title="Select Original File for Verification", filetypes=[("All files", "*.*")])
            if not self.file_path:
                messagebox.showerror("Error", "Original file is required for signature verification")
                return
        with open(self.file_path, "rb") as f:
            original_data = f.read()

        try:
            public_key.verify(
                signature,
                original_data,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256()
            )
            messagebox.showinfo("Success", "Signature verified successfully")
        except Exception as e:
            messagebox.showwarning("Warning", f"Signature verification failed: {str(e)}")

        save_path = filedialog.asksaveasfilename(defaultextension=".dec")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(decrypted_data)
            messagebox.showinfo("Success", "File decrypted and saved")

if __name__ == "__main__":
    root = tk.Tk()
    password_manager = PasswordManager()
    login_window = LoginWindow(root, password_manager)
    root.mainloop()
