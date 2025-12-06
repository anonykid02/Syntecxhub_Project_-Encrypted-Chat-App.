import socket
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
import secrets
import base64


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


HOST = "127.0.0.1"
PORT = 7000

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))
print("[+] Connected to server.")

# DH Key Exchange
private_key = secrets.randbelow(P-2)
public_key = pow(G, private_key, P)

server_pub = int(client.recv(4096).decode())
client.send(str(public_key).encode())

shared_secret = pow(server_pub, private_key, P)
AES_KEY = derive_aes_key(shared_secret)

print("[+] Secure AES key established.")

while True:
    msg = input("You: ").encode()
    client.send(encrypt_message(AES_KEY, msg))

    encrypted_reply = client.recv(2048)
    reply = decrypt_message(AES_KEY, encrypted_reply)
    print("[Server]:", reply)
