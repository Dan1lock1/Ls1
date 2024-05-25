import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import math

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def modinv(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = modinv(e, phi)
    return (n, e), (n, d)

def encrypt_rsa(plaintext, public_key):
    n, e = public_key
    plaintext_bytes = [ord(char) for char in plaintext]
    ciphertext = [pow(char, e, n) for char in plaintext_bytes]
    return ciphertext

def decrypt_rsa(ciphertext, private_key):
    n, d = private_key
    plaintext_bytes = [pow(char, d, n) for char in ciphertext]
    plaintext = ''.join(chr(byte) for byte in plaintext_bytes)
    return plaintext

def save_to_file(content, filename):
    with open(filename, 'w') as f:
        for item in content:
            f.write("%s\n" % item)

def read_from_file(filename):
    with open(filename, 'r') as f:
        return [int(line.strip()) for line in f]

def encrypt_text():
    plaintext = plaintext_entry.get("1.0", tk.END).strip()
    try:
        p = int(p_entry.get().strip())
        q = int(q_entry.get().strip())
    except ValueError:
        messagebox.showerror("Error", "p and q must be prime numbers")
        return
    
    if not plaintext or not p or not q:
        messagebox.showerror("Error", "Plaintext, p, and q must be provided")
        return
    
    public_key, private_key = generate_keys(p, q)
    ciphertext = encrypt_rsa(plaintext, public_key)
    save_to_file(ciphertext, 'encrypted_rsa_manual.txt')
    result_text.set(' '.join(map(str, ciphertext)))

def decrypt_text():
    try:
        p = int(p_entry.get().strip())
        q = int(q_entry.get().strip())
    except ValueError:
        messagebox.showerror("Error", "p and q must be prime numbers")
        return
    
    public_key, private_key = generate_keys(p, q)
    ciphertext = read_from_file('encrypted_rsa_manual.txt')
    try:
        plaintext = decrypt_rsa(ciphertext, private_key)
        result_text.set(plaintext)
    except Exception as e:
        messagebox.showerror("Error", str(e))

# GUI Setup
root = tk.Tk()
root.title("Manual RSA Encryption/Decryption")

mainframe = ttk.Frame(root, padding="10 10 10 10")
mainframe.grid(column=0, row=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Plaintext input
ttk.Label(mainframe, text="Text").grid(column=1, row=1, sticky=tk.W)
plaintext_entry = tk.Text(mainframe, width=50, height=10)
plaintext_entry.grid(column=2, row=1, sticky=(tk.W, tk.E))

# Prime numbers input
ttk.Label(mainframe, text="p").grid(column=1, row=2, sticky=tk.W)
p_entry = ttk.Entry(mainframe, width=20)
p_entry.grid(column=2, row=2, sticky=(tk.W, tk.E))

ttk.Label(mainframe, text="q").grid(column=1, row=3, sticky=tk.W)
q_entry = ttk.Entry(mainframe, width=20)
q_entry.grid(column=2, row=3, sticky=(tk.W, tk.E))

# Encrypt and Decrypt buttons
ttk.Button(mainframe, text="Encrypt", command=encrypt_text).grid(column=1, row=4, sticky=tk.W)
ttk.Button(mainframe, text="Decrypt", command=decrypt_text).grid(column=2, row=4, sticky=tk.W)

# Result display
result_text = tk.StringVar()
ttk.Label(mainframe, text="Result").grid(column=1, row=5, sticky=tk.W)
result_label = ttk.Label(mainframe, textvariable=result_text, wraplength=400)
result_label.grid(column=2, row=5, sticky=(tk.W, tk.E))

root.mainloop()
