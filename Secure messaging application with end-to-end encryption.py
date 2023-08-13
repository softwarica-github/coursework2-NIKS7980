from tkinter import *
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
import pyperclip

def generate_key():
    key = Fernet.generate_key()
    return key

def encrypt_text(key, text):
    cipher_suite = Fernet(key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text

def decrypt_text(key, encrypted_text):
    cipher_suite = Fernet(key)
    decrypted_text = cipher_suite.decrypt(encrypted_text)
    return decrypted_text.decode()

encryption_key = generate_key()

def encrypt():
    text = textl.get("1.0", "end-1c")

    encrypted_text = encrypt_text(encryption_key, text)
    encrypted_text_encoded = base64.b64encode(encrypted_text).decode()

    result_text.delete("1.0", END)
    result_text.insert("1.0", encrypted_text_encoded)

    messagebox.showinfo("Encryption Result", f"Encrypted Text: {encrypted_text_encoded}")

def decrypt():
    text = textl.get("1.0", "end-1c")

    encrypted_text = base64.b64decode(text.encode())
    decrypted_text = decrypt_text(encryption_key, encrypted_text)

    messagebox.showinfo("Decryption Result", f"Decrypted Text: {decrypted_text}")

def copy_to_clipboard():
    text = result_text.get("1.0", "end-1c")
    pyperclip.copy(text)
    messagebox.showinfo("Copy to Clipboard", "Text has been copied to the clipboard.")

def paste_from_clipboard():
    text_from_clipboard = pyperclip.paste()
    textl.delete("1.0", END)
    textl.insert("1.0", text_from_clipboard)

def login():
    global login_screen
    global code_entry

    login_screen = Tk()
    login_screen.geometry("300x200")
    login_screen.title("Login")

    code_label = Label(login_screen, text="Enter secret code:", font=("Arial", 14))
    code_label.pack(pady=20)

    code_entry = Entry(login_screen, width=19, bd=0, font=("Arial", 14), show="*")
    code_entry.pack()

    login_button = Button(login_screen, text="Login", font=("Arial", 14), command=authenticate)
    login_button.pack(pady=20)

    login_screen.mainloop()

def authenticate():
    entered_code = code_entry.get()
    if entered_code == "password123":
        login_screen.destroy()
        main_screen()
    else:
        messagebox.showerror("Authentication Failed", "Invalid code entered.")

def main_screen():
    global screen
    global textl
    global result_text

    screen = Tk()
    screen.geometry("375x398")
    screen.title("Secure Messaging Application with End-to-End Encryption")

    # Icon
    image_icon = PhotoImage(file="/home/kali/Downloads/4631949.png")
    screen.iconphoto(False, image_icon)

    # Style
    bg_color = "#F4F4F4"
    fg_color = "#333333"
    font_style = ("Helvetica", 13)

    screen.config(bg=bg_color)

    text_label = Label(screen, text="Enter text for encryption and decryption", fg=fg_color, font=font_style)
    text_label.pack(pady=10)

    textl = Text(screen, font=("Roboto", 14), bg="white", relief=GROOVE, wrap=WORD, bd=0, height=4)
    textl.pack(padx=10)

    key_label = Label(screen, text="Enter secret key for encryption and decryption", fg=fg_color, font=font_style)
    key_label.pack(pady=10)

    code = Entry(screen, width=19, bd=0, font=("Arial", 20), show="*")
    code.pack()

    encrypt_button = Button(screen, text="Encrypt", font=("Calibri", 16), command=encrypt, bg="#4CAF50", fg="white")
    encrypt_button.pack(pady=10)

    decrypt_button = Button(screen, text="Decrypt", font=("Calibri", 16), command=decrypt, bg="#FF5722", fg="white")
    decrypt_button.pack(pady=10)

    result_label = Label(screen, text="Encryption Result:", fg=fg_color, font=font_style)
    result_label.pack(pady=10)

    result_text = Text(screen, font=("Roboto", 14), bg="white", relief=GROOVE, wrap=WORD, bd=0, height=4)
    result_text.pack(padx=10)

    copy_button = Button(screen, text="Copy Result", font=("Calibri", 16), command=copy_to_clipboard, bg="#2196F3", fg="white")
    copy_button.pack(pady=10)

    paste_button = Button(screen, text="Paste", font=("Calibri", 16), command=paste_from_clipboard, bg="#607D8B", fg="white")
    paste_button.pack(pady=10)

    screen.mainloop()

login()
