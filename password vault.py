import os
import json
import base64
import secrets
import string
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

VAULT_FILE = "vault.enc"

# --- UI THEME SETTINGS ---
ctk.set_appearance_mode("dark")  # Modes: "System" (standard), "Dark", "Light"
ctk.set_default_color_theme("blue")  # Themes: "blue" (standard), "green", "dark-blue"

# --- CRYPTOGRAPHY LOGIC (Unchanged) ---
def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master_password.encode()))

def create_vault(master_pw):
    salt = os.urandom(16)
    key = derive_key(master_pw, salt)
    empty_data = json.dumps({}).encode()
    f = Fernet(key)
    with open(VAULT_FILE, "wb") as file:
        file.write(salt + f.encrypt(empty_data))

def load_vault(master_password):
    if not os.path.exists(VAULT_FILE):
        return None
    with open(VAULT_FILE, "rb") as file:
        content = file.read()
    salt, encrypted_data = content[:16], content[16:]
    key = derive_key(master_password, salt)
    f = Fernet(key)
    try:
        return json.loads(f.decrypt(encrypted_data).decode())
    except InvalidToken:
        return False 

def save_vault(master_password, data):
    with open(VAULT_FILE, "rb") as file:
        salt = file.read()[:16]
    key = derive_key(master_password, salt)
    f = Fernet(key)
    with open(VAULT_FILE, "wb") as file:
        file.write(salt + f.encrypt(json.dumps(data).encode()))


# --- MODERN GUI LOGIC ---
class PasswordVaultApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Vault")
        self.root.geometry("450x550")
        self.root.resizable(False, False)
        
        self.master_password = ""
        self.vault_data = {}

        # Main container to hold our screens
        self.container = ctk.CTkFrame(self.root, fg_color="transparent")
        self.container.pack(fill="both", expand=True, padx=20, pady=20)

        self.show_login_screen()

    def clear_container(self):
        """Removes all widgets from the main container for a clean transition."""
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self.clear_container()

        # Header Image / Icon (Simulated with text for now)
        ctk.CTkLabel(self.container, text="🛡️", font=("Arial", 60)).pack(pady=(20, 10))
        ctk.CTkLabel(self.container, text="Secure Vault", font=("Arial", 24, "bold")).pack(pady=(0, 30))

        self.error_label = ctk.CTkLabel(self.container, text="", text_color="red")
        self.error_label.pack()

        if not os.path.exists(VAULT_FILE):
            ctk.CTkLabel(self.container, text="Welcome. Let's set up your master key.", text_color="gray").pack(pady=(0, 10))
            self.pw_entry = ctk.CTkEntry(self.container, placeholder_text="Create Master Password", show="•", width=250, height=40)
            self.pw_entry.pack(pady=10)
            btn = ctk.CTkButton(self.container, text="Initialize Vault", command=self.setup_new_vault, width=250, height=40, fg_color="#2b9348", hover_color="#007f5f")
            btn.pack(pady=20)
        else:
            ctk.CTkLabel(self.container, text="Welcome back. Enter your key to unlock.", text_color="gray").pack(pady=(0, 10))
            self.pw_entry = ctk.CTkEntry(self.container, placeholder_text="Master Password", show="•", width=250, height=40)
            self.pw_entry.pack(pady=10)
            self.pw_entry.bind('<Return>', lambda event: self.unlock_vault()) # Press Enter to login
            btn = ctk.CTkButton(self.container, text="Unlock", command=self.unlock_vault, width=250, height=40)
            btn.pack(pady=20)

    def setup_new_vault(self):
        pw = self.pw_entry.get()
        if len(pw) < 4:
            self.error_label.configure(text="Password must be at least 4 characters.")
            return
        create_vault(pw)
        self.show_login_screen()
        self.error_label.configure(text="Vault created! Please log in.", text_color="green")

    def unlock_vault(self):
        pw = self.pw_entry.get()
        data = load_vault(pw)
        if data is False:
            self.error_label.configure(text="Incorrect Master Password", text_color="red")
            # Simple shake animation effect on error
            for i in range(0, 20, 5):
                self.root.geometry(f"450x550+{self.root.winfo_x() + i}+{self.root.winfo_y()}")
                self.root.update()
                self.root.geometry(f"450x550+{self.root.winfo_x() - i}+{self.root.winfo_y()}")
                self.root.update()
        else:
            self.master_password = pw
            self.vault_data = data
            self.show_main_vault()

    def show_main_vault(self):
        self.clear_container()

        # Top Bar
        top_frame = ctk.CTkFrame(self.container, fg_color="transparent")
        top_frame.pack(fill="x", pady=(0, 10))
        ctk.CTkLabel(top_frame, text="✅ Vault Unlocked", font=("Arial", 18, "bold"), text_color="#2b9348").pack(side="left")
        
        # FIXED: root.destroy() cleanly kills the app
        ctk.CTkButton(top_frame, text="Lock & Exit", command=self.root.destroy, width=100, fg_color="#d90429", hover_color="#ef233c").pack(side="right")

        # Add New Account Section
        add_frame = ctk.CTkFrame(self.container)
        add_frame.pack(fill="x", pady=10, padx=5)
        
        self.new_acc_entry = ctk.CTkEntry(add_frame, placeholder_text="App / Website Name", width=200)
        self.new_acc_entry.pack(side="left", padx=10, pady=10)
        
        ctk.CTkButton(add_frame, text="Generate & Save", command=self.add_account, width=120).pack(side="right", padx=10, pady=10)

        # Scrollable Account List (Replaces the ugly Listbox)
        ctk.CTkLabel(self.container, text="Your Saved Accounts", font=("Arial", 14)).pack(anchor="w", pady=(10, 5))
        self.scroll_frame = ctk.CTkScrollableFrame(self.container, width=400, height=250)
        self.scroll_frame.pack(fill="both", expand=True)

        self.refresh_list()

    def refresh_list(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        if not self.vault_data:
            ctk.CTkLabel(self.scroll_frame, text="No accounts saved yet.", text_color="gray").pack(pady=20)
            return

        for account in sorted(self.vault_data.keys()):
            card = ctk.CTkFrame(self.scroll_frame, fg_color="#2b2b2b")
            card.pack(fill="x", pady=5, padx=5)
            
            ctk.CTkLabel(card, text=account, font=("Arial", 14, "bold")).pack(side="left", padx=15, pady=10)
            ctk.CTkButton(card, text="Reveal", width=80, command=lambda acc=account: self.view_password(acc)).pack(side="right", padx=10, pady=10)

    def add_account(self):
        account = self.new_acc_entry.get().strip()
        if not account:
            return
        if account in self.vault_data:
            messagebox.showwarning("Warning", "Account already exists!")
            return
        
        new_pw = generate_password(16)
        self.vault_data[account] = new_pw
        save_vault(self.master_password, self.vault_data)
        
        self.new_acc_entry.delete(0, 'end')
        self.refresh_list()
        self.view_password(account, is_new=True)

    def view_password(self, account, is_new=False):
        password = self.vault_data[account]
        
        # Modern Popup Window
        top = ctk.CTkToplevel(self.root)
        top.title(account)
        top.geometry("350x200")
        top.attributes("-topmost", True) # Keep on top
        
        title_text = "New Password Generated!" if is_new else f"Password for {account}"
        ctk.CTkLabel(top, text=title_text, font=("Arial", 16, "bold")).pack(pady=(20, 10))
        
        pw_entry = ctk.CTkEntry(top, width=250, font=("Courier", 14), justify="center")
        pw_entry.insert(0, password)
        pw_entry.configure(state="readonly")
        pw_entry.pack(pady=10)
        
        def copy_to_clipboard():
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            btn.configure(text="Copied!", fg_color="#2b9348", hover_color="#2b9348")
            
        btn = ctk.CTkButton(top, text="Copy to Clipboard", command=copy_to_clipboard)
        btn.pack(pady=10)

if __name__ == "__main__":
    app_root = ctk.CTk()
    app = PasswordVaultApp(app_root)
    app_root.mainloop()
