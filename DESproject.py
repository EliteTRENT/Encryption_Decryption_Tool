#Importing Modules
import tkinter as tk
from tkinter import messagebox
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad,unpad
import os
import binascii

# Global variables
key = None
IV = None

#Functions
def isHexadecimal(text):
    text = text.replace(" ","")
    return all(c in '0123456789abcdefABCDEF' for c in text)

def encrypt():
    global key, IV
    input_text_content = input_text.get("1.0",tk.END).strip()
    if not isHexadecimal(input_text_content):
        key = os.urandom(8)
        IV = os.urandom(8)
        cipher = DES.new(key,DES.MODE_CBC,IV)
        input_text_bytes = input_text_content.encode('utf-8')
        padded_text = pad(input_text_bytes,DES.block_size)
        ciphertext = cipher.encrypt(padded_text)
        encrypted_text = binascii.hexlify(ciphertext).decode()
        output_text.delete("1.0",tk.END)
        output_text.insert(tk.END,encrypted_text)
    else:
        messagebox.showwarning("Warning","Input text seems to be ciphertext. Please provide plaintext for encryption.")

def decrypt():
    input_text_content = input_text.get("1.0",tk.END).strip()

    if not isHexadecimal(input_text_content):
        messagebox.showwarning("Warning","Input text seems to be plain text. Please provide cipher text for decryption.")
    else:
        input_text_bytes = binascii.unhexlify(input_text_content)
        cipher = DES.new(key,DES.MODE_CBC,IV)
        decrypted_padded_text = cipher.decrypt(input_text_bytes)
        decrypted_text = unpad(decrypted_padded_text,DES.block_size).decode('utf-8')
        output_text.delete("1.0",tk.END)
        output_text.insert(tk.END,decrypted_text)

def clear_text():
    input_text.delete("1.0",tk.END)
    output_text.delete("1.0",tk.END)
    
#Creating entities of GUI
root = tk.Tk()
root.title("Message Encryption & Decryption")
root.geometry("400x300")
input_label = tk.Label(root,text="Input Text: ")
input_label.pack()
input_text = tk.Text(root,height=5,width=70)
input_text.pack()
output_label = tk.Label(root,text="Result: ")
output_label.pack()
output_text = tk.Text(root,height=5,width=70) 
output_text.pack()
button_frame = tk.Frame(root)
button_frame.pack(pady=15)
encrypt_button = tk.Button(button_frame,text="Encrypt",command=encrypt)
encrypt_button.grid(row=0,column=0,padx=10)
decrypt_button = tk.Button(button_frame,text="Decrypt",command=decrypt)
decrypt_button.grid(row=0,column=1,padx=10)
clear_button = tk.Button(button_frame,text="Clear",command=clear_text)
clear_button.grid(row=0,column=2,padx=10)
root.mainloop()

