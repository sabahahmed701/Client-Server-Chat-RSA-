#server.py
import tkinter as tk
from tkinter import scrolledtext
import socket
from threading import Thread
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    return key, key.publickey()

def encrypt_message(message, key):
    cipher_rsa = PKCS1_OAEP.new(key)
    encrypted_message = cipher_rsa.encrypt(message.encode("utf-8"))
    return encrypted_message

def decrypt_message(encrypted_message, key):
    decipher_rsa = PKCS1_OAEP.new(key)
    decrypted_message = decipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode("utf-8")

def send_message():
    message = my_message.get()
    text_area.insert(tk.END, "Server: " + message + "\n")
    encrypted_message = encrypt_message(message, client_public_key)
    conn.send(encrypted_message)
    my_message.set("")
    text_area.insert(tk.END, "Server (Encrypted): " + encrypted_message.hex() + "\n") 

def receive_messages():
    while True:
        try:
            encrypted_message = conn.recv(2048)
            message = decrypt_message(encrypted_message, private_key)
            text_area.insert(tk.END, "Client: " + message + "\n")  
        except OSError:
            break

root = tk.Tk()
root.title("Server")

text_area = scrolledtext.ScrolledText(root)
text_area.pack(side=tk.TOP, fill=tk.BOTH, expand=tk.YES)

my_message = tk.StringVar()
entry_field = tk.Entry(root, textvariable=my_message)
entry_field.pack(side=tk.BOTTOM, fill=tk.BOTH, expand=tk.YES)

send_button = tk.Button(root, text="Send", command=send_message)
send_button.pack(side=tk.BOTTOM)

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('127.0.0.1', 12345))
server_socket.listen(1)
conn, addr = server_socket.accept()

private_key, public_key = generate_rsa_key_pair()
conn.sendall(public_key.exportKey(format='PEM'))

client_public_key_pem = conn.recv(4096)
client_public_key = RSA.import_key(client_public_key_pem)

receive_thread = Thread(target=receive_messages)
receive_thread.start()

tk.mainloop()
