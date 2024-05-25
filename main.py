import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    if not plaintext:
        messagebox.showerror("Error", "Plaintext must be provided")
        return

    ciphertext = public_key.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    save_to_file(ciphertext, 'encrypted_rsa.txt')
    result_text.set(ciphertext.hex())

def decrypt_text():
    ciphertext = read_from_file('encrypted_rsa.txt')
    try:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        result_text.set(plaintext.decode())
    except Exception as e:
        messagebox.showerror("Error", str(e))

def save_to_file(content, filename):
    with open(filename, 'wb') as f:
        f.write(content)

def read_from_file(filename):
    with open(filename, 'rb') as f:
        return f.read()

# GUI Setup
root = tk.Tk()
root.title("RSA Encryption/Decryption")

mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Plaintext input
ttk.Label(mainframe, text="Text").grid(column=1, row=1, sticky=tk.W)
plaintext_entry = tk.Text(mainframe, width=50, height=10)
plaintext_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))

# Encrypt and Decrypt buttons
ttk.Button(mainframe, text="Encrypt", command=encrypt_text).grid(column=1, row=2, sticky=tk.W)
ttk.Button(mainframe, text="Decrypt", command=decrypt_text).grid(column=2, row=2, sticky=tk.W)

# Result display
result_text = tk.StringVar()
ttk.Label(mainframe, text="Result").grid(column=1, row=3, sticky=tk.W)
result_label = ttk.Label(mainframe, textvariable=result_text, wraplength=400)
result_label.grid(column=2, row=3, sticky=(tk.W, tk.E))

root.mainloop()
