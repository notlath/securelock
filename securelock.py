"""
SecureLock - File Encryption/Decryption Tool
--------------------------------------------
Provides dual-layer encryption (AES-256-GCM + RSA-3072) with self-destruct functionality.
"""

import os
import json
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib
from typing import Tuple, Dict, Optional, Union

# Import cryptography libraries
try:
    from Crypto.Cipher import AES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    messagebox.showerror("Missing Dependencies", 
                         "Please install required packages using: pip install pycryptodome")
    exit(1)

class SecureLock:
    """Main SecureLock application for file encryption and decryption."""
    
    def __init__(self):
        """Initialize the SecureLock application and GUI."""
        self.root = tk.Tk()
        self.root.title("SecureLock - Secure File Encryption")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        
        # Set application icon and theme
        self.root.configure(bg="#f0f0f0")
        
        # Directory paths
        self.keys_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys")
        if not os.path.exists(self.keys_dir):
            os.makedirs(self.keys_dir)
            
        # Tracking for self-destruct mechanism
        self.attempts_registry = {}  # Tracks decryption attempts per file
        self.attempts_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".attempts")
        self.load_attempts()
        
        # Setup GUI components
        self.setup_gui()
        
        # Check if RSA keys exist, if not prompt for generation
        self.check_keys()
    
    def setup_gui(self):
        """Set up the GUI components."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title and instructions
        title_label = ttk.Label(
            main_frame, 
            text="SecureLock", 
            font=("Arial", 16, "bold")
        )
        title_label.pack(pady=10)
        
        instruction_label = ttk.Label(
            main_frame,
            text="Encrypt or decrypt files with dual-layer AES-256-GCM and RSA-3072 encryption.",
            wraplength=500
        )
        instruction_label.pack(pady=5)
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=10)
        
        self.file_path_var = tk.StringVar()
        self.file_path_var.set("No file selected")
        
        file_path_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=50, state="readonly")
        file_path_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        browse_button = ttk.Button(file_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.RIGHT, padx=5)
        
        # Password frame
        password_frame = ttk.LabelFrame(main_frame, text="RSA Key Password", padding=10)
        password_frame.pack(fill=tk.X, pady=10)
        
        self.password_var = tk.StringVar()
        
        password_label = ttk.Label(password_frame, text="Password:")
        password_label.pack(side=tk.LEFT, padx=5)
        
        self.password_entry = ttk.Entry(password_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Action buttons frame
        action_frame = ttk.Frame(main_frame, padding=10)
        action_frame.pack(fill=tk.X, pady=10)
        
        encrypt_button = ttk.Button(action_frame, text="🔒 Encrypt", command=self.encrypt_file)
        encrypt_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        decrypt_button = ttk.Button(action_frame, text="🔓 Decrypt", command=self.decrypt_file)
        decrypt_button.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=(5, 2)
        )
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Key management frame
        key_frame = ttk.Frame(main_frame, padding=10)
        key_frame.pack(fill=tk.X, pady=5)
        
        generate_keys_button = ttk.Button(
            key_frame, 
            text="Generate New RSA Keys", 
            command=self.generate_rsa_keys
        )
        generate_keys_button.pack(side=tk.LEFT, padx=5)
    
    def check_keys(self):
        """Check if RSA keys exist and prompt for generation if needed."""
        public_key_path = os.path.join(self.keys_dir, "public.pem")
        private_key_path = os.path.join(self.keys_dir, "private.pem")
        
        if not (os.path.exists(public_key_path) and os.path.exists(private_key_path)):
            result = messagebox.askyesno(
                "First-Time Setup",
                "RSA key pair not found. Would you like to generate a new key pair now?\n\n"
                "Note: You'll need to set a password to protect your private key."
            )
            if result:
                self.generate_rsa_keys()
            else:
                self.status_var.set("Warning: No RSA keys available. Encryption/decryption not possible.")
    
    def generate_rsa_keys(self):
        """Generate a new RSA key pair."""
        # Get password for private key
        password_dialog = tk.Toplevel(self.root)
        password_dialog.title("Set Private Key Password")
        password_dialog.geometry("400x200")
        password_dialog.resizable(False, False)
        password_dialog.transient(self.root)
        password_dialog.grab_set()
        
        ttk.Label(
            password_dialog,
            text="Create a strong password to protect your RSA private key:",
            wraplength=350,
            padding=(20, 10)
        ).pack()
        
        password_var = tk.StringVar()
        confirm_var = tk.StringVar()
        
        password_frame = ttk.Frame(password_dialog, padding=(20, 5))
        password_frame.pack(fill=tk.X)
        
        ttk.Label(password_frame, text="Password:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(password_frame, textvariable=password_var, show="*").grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(password_frame, text="Confirm:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(password_frame, textvariable=confirm_var, show="*").grid(row=1, column=1, padx=5, pady=5)
        
        def validate_and_generate():
            password = password_var.get()
            confirm = confirm_var.get()
            
            if not password:
                messagebox.showerror("Error", "Password cannot be empty.")
                return
            
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match.")
                return
            
            if len(password) < 8:
                messagebox.showerror("Error", "Password must be at least 8 characters.")
                return
            
            # Close dialog and generate keys
            password_dialog.destroy()
            self._generate_key_pair(password)
        
        button_frame = ttk.Frame(password_dialog, padding=(20, 10))
        button_frame.pack(fill=tk.X)
        
        ttk.Button(
            button_frame,
            text="Generate Keys",
            command=validate_and_generate
        ).pack(side=tk.RIGHT, padx=5)
        
        ttk.Button(
            button_frame,
            text="Cancel",
            command=password_dialog.destroy
        ).pack(side=tk.RIGHT, padx=5)
        
        # Center the dialog on the main window
        password_dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (password_dialog.winfo_width() // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (password_dialog.winfo_height() // 2)
        password_dialog.geometry(f"+{x}+{y}")
    
    def _generate_key_pair(self, password: str):
        """Generate and save RSA key pair."""
        try:
            self.status_var.set("Generating RSA key pair...")
            self.root.update()
            
            # Generate RSA key pair (3072 bits)
            key = RSA.generate(3072)
            
            # Export private key with password protection
            private_key = key.export_key(passphrase=password, pkcs=8, 
                                        protection="scryptAndAES128-CBC")
            
            # Export public key
            public_key = key.publickey().export_key()
            
            # Save keys to files
            with open(os.path.join(self.keys_dir, "private.pem"), "wb") as f:
                f.write(private_key)
            
            with open(os.path.join(self.keys_dir, "public.pem"), "wb") as f:
                f.write(public_key)
            
            self.status_var.set("RSA key pair generated successfully.")
            messagebox.showinfo(
                "Success", 
                "RSA key pair generated successfully.\n\n"
                "IMPORTANT: Keep your password safe. If you lose it, you won't be able to decrypt your files."
            )
        except Exception as e:
            self.status_var.set(f"Error generating RSA keys: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate RSA keys: {str(e)}")
    
    def browse_file(self):
        """Open file browser dialog to select a file."""
        file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[("All Files", "*.*"), (".securelock Files", "*.securelock")]
        )
        
        if file_path:
            self.file_path_var.set(file_path)
            
            # Auto-detect if it's an encrypted file
            if file_path.endswith(".securelock"):
                self.status_var.set("Encrypted file selected. Use Decrypt button to decrypt.")
            else:
                self.status_var.set("File selected. Use Encrypt button to encrypt.")
    
    def encrypt_file(self):
        """Encrypt the selected file using AES-256-GCM and RSA-3072."""
        file_path = self.file_path_var.get()
        
        if file_path == "No file selected":
            messagebox.showerror("Error", "Please select a file to encrypt.")
            return
        
        if file_path.endswith(".securelock"):
            messagebox.showerror("Error", "This file is already encrypted.")
            return
        
        try:
            # Load RSA public key
            public_key_path = os.path.join(self.keys_dir, "public.pem")
            
            if not os.path.exists(public_key_path):
                messagebox.showerror("Error", "RSA public key not found. Please generate RSA keys first.")
                return
            
            with open(public_key_path, "rb") as f:
                public_key = RSA.import_key(f.read())
            
            # Read file content
            with open(file_path, "rb") as f:
                file_data = f.read()
            
            # Calculate SHA-256 hash of original file for integrity check
            file_hash = SHA256.new(file_data).digest()
            
            # Generate random AES key (256 bits)
            aes_key = get_random_bytes(32)
            
            # Encrypt file data with AES-256-GCM
            aes_cipher = AES.new(aes_key, AES.MODE_GCM)
            ciphertext, tag = aes_cipher.encrypt_and_digest(file_data)
            nonce = aes_cipher.nonce
            
            # Encrypt AES key with RSA-OAEP
            rsa_cipher = PKCS1_OAEP.new(public_key)
            encrypted_aes_key = rsa_cipher.encrypt(aes_key)
            
            # Prepare metadata
            metadata = {
                "version": "1.0",
                "encryption": "AES-256-GCM+RSA-3072",
                "original_filename": os.path.basename(file_path),
                "original_extension": os.path.splitext(file_path)[1],
                "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode('utf-8'),
                "nonce": base64.b64encode(nonce).decode('utf-8'),
                "tag": base64.b64encode(tag).decode('utf-8'),
                "file_hash": base64.b64encode(file_hash).decode('utf-8')
            }
            
            # Serialize metadata to JSON
            metadata_json = json.dumps(metadata).encode('utf-8')
            
            # Prepare output file path
            output_path = f"{file_path}.securelock"
            
            # Write encrypted file
            with open(output_path, "wb") as f:
                # Format: [metadata size (4 bytes)][metadata (JSON)][encrypted data]
                f.write(len(metadata_json).to_bytes(4, byteorder='big'))
                f.write(metadata_json)
                f.write(ciphertext)
            
            self.status_var.set(f"File encrypted successfully: {output_path}")
            messagebox.showinfo("Success", "File encrypted successfully!")
            
            # Update file path to the encrypted file
            self.file_path_var.set(output_path)
            
        except Exception as e:
            self.status_var.set(f"Encryption error: {str(e)}")
            messagebox.showerror("Encryption Error", f"Failed to encrypt file: {str(e)}")
    
    def decrypt_file(self):
        """Decrypt the selected .securelock file."""
        file_path = self.file_path_var.get()
        password = self.password_var.get()
        
        if file_path == "No file selected":
            messagebox.showerror("Error", "Please select a file to decrypt.")
            return
        
        if not file_path.endswith(".securelock"):
            messagebox.showerror("Error", "This is not a .securelock encrypted file.")
            return
        
        if not password:
            messagebox.showerror("Error", "Please enter the RSA private key password.")
            return
        
        # Check for failed attempts and self-destruct if needed
        attempts = self.get_attempts(file_path)
        if attempts >= 3:
            messagebox.showerror(
                "Self-Destruct Triggered", 
                "The file has been deleted due to too many failed decryption attempts."
            )
            self.status_var.set("Self-destruct triggered. File deleted.")
            return
        
        try:
            # Load RSA private key
            private_key_path = os.path.join(self.keys_dir, "private.pem")
            
            if not os.path.exists(private_key_path):
                messagebox.showerror("Error", "RSA private key not found. Please generate RSA keys first.")
                return
            
            # Read encrypted file
            with open(file_path, "rb") as f:
                # Read metadata size
                metadata_size = int.from_bytes(f.read(4), byteorder='big')
                
                # Read metadata JSON
                metadata_json = f.read(metadata_size)
                metadata = json.loads(metadata_json.decode('utf-8'))
                
                # Read encrypted data
                ciphertext = f.read()
            
            # Extract encryption parameters from metadata
            encrypted_aes_key = base64.b64decode(metadata["encrypted_aes_key"])
            nonce = base64.b64decode(metadata["nonce"])
            tag = base64.b64decode(metadata["tag"])
            file_hash = base64.b64decode(metadata["file_hash"])
            original_filename = metadata["original_filename"]
            
            try:
                # Import private key with password
                with open(private_key_path, "rb") as f:
                    private_key = RSA.import_key(f.read(), passphrase=password)
                
                # Decrypt AES key with RSA
                rsa_cipher = PKCS1_OAEP.new(private_key)
                aes_key = rsa_cipher.decrypt(encrypted_aes_key)
                
                # Decrypt file with AES-GCM
                aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
                decrypted_data = aes_cipher.decrypt_and_verify(ciphertext, tag)
                
                # Verify integrity with SHA-256
                computed_hash = SHA256.new(decrypted_data).digest()
                if computed_hash != file_hash:
                    messagebox.showerror("Integrity Error", 
                                        "File integrity check failed. The file may be corrupted.")
                    return
                
                # Determine output filename
                output_dir = os.path.dirname(file_path)
                base_name = os.path.splitext(original_filename)[0]
                ext = os.path.splitext(original_filename)[1]
                
                # Create unique output filename
                output_path = os.path.join(output_dir, f"{base_name}_decrypted{ext}")
                counter = 1
                while os.path.exists(output_path):
                    output_path = os.path.join(output_dir, f"{base_name}_decrypted_{counter}{ext}")
                    counter += 1
                
                # Write decrypted file
                with open(output_path, "wb") as f:
                    f.write(decrypted_data)
                
                # Reset attempts counter
                self.reset_attempts(file_path)
                
                self.status_var.set(f"File decrypted successfully: {output_path}")
                messagebox.showinfo("Success", "File decrypted successfully!")
                
                # Update file path to the decrypted file
                self.file_path_var.set(output_path)
                
            except (ValueError, KeyError) as e:
                # Handle decryption failure (likely wrong password)
                self.increment_attempts(file_path)
                attempts = self.get_attempts(file_path)
                
                if attempts >= 3:
                    # Self-destruct triggered - delete the encrypted file
                    os.remove(file_path)
                    
                    # Also try to delete the original file if it exists
                    # Remove the .securelock extension to get the original file path
                    original_file_path = file_path[:-11]  # Remove '.securelock'
                    if os.path.exists(original_file_path):
                        try:
                            os.remove(original_file_path)
                            deletion_message = "Both encrypted and original files have been deleted."
                        except:
                            deletion_message = "Encrypted file has been deleted. Could not delete original file."
                    else:
                        deletion_message = "Encrypted file has been deleted. Original file not found."
                    
                    self.reset_attempts(file_path)
                    messagebox.showerror(
                        "Self-Destruct Triggered", 
                        f"Self-destruct mechanism activated after 3 failed attempts.\n\n{deletion_message}"
                    )
                    self.status_var.set("Self-destruct triggered. Files deleted.")
                    self.file_path_var.set("No file selected")
                else:
                    messagebox.showerror(
                        "Decryption Error", 
                        f"Failed to decrypt file. Incorrect password?\n\n"
                        f"{3 - attempts} attempts remaining before self-destruct."
                    )
                    self.status_var.set(f"Decryption failed. {3 - attempts} attempts remaining.")
        
        except Exception as e:
            self.status_var.set(f"Decryption error: {str(e)}")
            messagebox.showerror("Decryption Error", f"Failed to decrypt file: {str(e)}")
    
    def get_attempts(self, file_path: str) -> int:
        """Get the number of failed attempts for a file."""
        file_id = self._get_file_id(file_path)
        return self.attempts_registry.get(file_id, 0)
    
    def increment_attempts(self, file_path: str) -> None:
        """Increment the failed attempts counter for a file."""
        file_id = self._get_file_id(file_path)
        self.attempts_registry[file_id] = self.attempts_registry.get(file_id, 0) + 1
        self.save_attempts()
    
    def reset_attempts(self, file_path: str) -> None:
        """Reset the failed attempts counter for a file."""
        file_id = self._get_file_id(file_path)
        if file_id in self.attempts_registry:
            del self.attempts_registry[file_id]
            self.save_attempts()
    
    def _get_file_id(self, file_path: str) -> str:
        """Generate a unique identifier for a file."""
        if os.path.exists(file_path):
            # Use file path and size as identifiers
            file_size = os.path.getsize(file_path)
            file_mtime = os.path.getmtime(file_path)
            file_id = f"{file_path}|{file_size}|{file_mtime}"
            return hashlib.sha256(file_id.encode()).hexdigest()
        return hashlib.sha256(file_path.encode()).hexdigest()
    
    def load_attempts(self) -> None:
        """Load failed attempts from file."""
        if os.path.exists(self.attempts_file):
            try:
                with open(self.attempts_file, "r") as f:
                    self.attempts_registry = json.load(f)
            except (json.JSONDecodeError, IOError):
                self.attempts_registry = {}
        else:
            self.attempts_registry = {}
    
    def save_attempts(self) -> None:
        """Save failed attempts to file."""
        try:
            with open(self.attempts_file, "w") as f:
                json.dump(self.attempts_registry, f)
        except IOError:
            pass  # Silently fail if we can't write to the file
    
    def run(self) -> None:
        """Run the SecureLock application."""
        self.root.mainloop()


if __name__ == "__main__":
    app = SecureLock()
    app.run()