import socket
import threading
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import secrets
import base64
import os

# ---------------------
# Diffie-Hellman Params
# ---------------------
P = int("""FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1
29024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD
3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C
42E9A63A3620FFFFFFFFFFFFFFFF""".replace("\n",""), 16)
G = 2

def derive_aes_key(shared_secret):
    return SHA256.new(str(shared_secret).encode()).digest()

def pad(data):
    return data + b" " * (16 - len(data) % 16)

def encrypt_message(key, message):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(pad(message)))

def decrypt_message(key, encrypted_data):
    raw = base64.b64decode(encrypted_data)
    iv = raw[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.decrypt(raw[16:]).rstrip().decode()


# ---------------------
# Logging
# ---------------------
os.makedirs("logs", exist_ok=True)

def log_message(client_id, direction, message):
    with open(f"logs/client_{client_id}.log", "a") as log_file:
        log_file.write(f"{direction}: {message}\n")


# ---------------------
# Client Handler
# ---------------------
def handle_client(conn, addr, client_id):
    print(f"[+] Handling new client {client_id} {addr}")

    # DH key exchange
    private_key = secrets.randbelow(P-2)
    public_key = pow(G, private_key, P)

    conn.send(str(public_key).encode())
    client_pub = int(conn.recv(4096).decode())

    shared_secret = pow(client_pub, private_key, P)
    AES_KEY = derive_aes_key(shared_secret)

    print(f"[+] Client {client_id} AES key established.")

    while True:
        try:
            encrypted_data = conn.recv(2048)
            if not encrypted_data:
                break

            message = decrypt_message(AES_KEY, encrypted_data)
            print(f"[Client {client_id}] {message}")

            log_message(client_id, "Received", message)

            reply = f"Server ACK (You said: {message})".encode()
            enc_reply = encrypt_message(AES_KEY, reply)
            conn.send(enc_reply)

            log_message(client_id, "Sent", reply.decode())

        except Exception:
            break

    print(f"[-] Client {client_id} disconnected.")
    conn.close()


# ---------------------
# Main Server Loop
# ---------------------
HOST = "127.0.0.1"
PORT = 7000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen(5)

print(f"[+] Server running on {HOST}:{PORT}")

client_count = 0
while True:
    conn, addr = server.accept()
    client_count += 1

    print(f"[+] Client {client_count} connected from {addr}")
    threading.Thread(target=handle_client, args=(conn, addr, client_count)).start()
