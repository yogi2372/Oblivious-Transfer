from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import socket
import secrets
from math import gcd
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def generate_random(min_value, max_value):
    return secrets.randbelow(max_value - min_value + 1) + min_value

def derive_aes_key(shared_secret):
    # Derive an AES key from SS using PBKDF2
    salt = b"salt_for_kdf" 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key size
        salt=salt,
        iterations=100000,  # Recommended no for PBKDF2
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_secret)
    return aes_key

def modular_inverse(a, m):
    if gcd(a, m) != 1:
        raise ValueError("Modular inverse does not exist.")
    return pow(a, m-2, m)

def aes_decrypt(key, encrypted_data):
    # Separate the Initialization Vector (IV) from the encrypted data
    iv = encrypted_data[:16]
    encrypted_message = encrypted_data[16:]

    # Create an AES cipher instance with Cipher Block Chaining (CBC) mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the data in chunks
    decrypted_chunks = []
    decryptor = cipher.decryptor()
    for i in range(0, len(encrypted_message), 16):
        chunk = encrypted_message[i:i+16]
        decrypted_chunks.append(decryptor.update(chunk))

    # Finalize decryption and concatenate decrypted chunks
    decrypted_message = b"".join(decrypted_chunks)
    decrypted_message += decryptor.finalize()

    # Unpad the message to remove padding using PKCS7 padding
    unpadder = padding.PKCS7(128).unpadder()
    message = unpadder.update(decrypted_message) + unpadder.finalize()

    return message


def exchange_numbers(conn):
    data = conn.recv(64)
    publickeyclient = int.from_bytes(data, 'big')
    print("Public key of client:", publickeyclient)

    mod =  9408805709926587341536627748682697267538057541842091816614276447848922965178961722305792046071437529806027256480806697858153181434361724972502258651588439
    gen = 2

    private_key = generate_random(2, mod - 2)

    publickey = pow(gen, private_key, mod)
   
    print("Enter choice bit:")
    c = int(input())

    if c == 0:
        print("sending if c=0", publickey, "\n")
        conn.send(publickey.to_bytes(64, 'big'))
    else:
        p = (publickey * publickeyclient) % mod
        print("sending if c=1", p, "\n")
        conn.send(p.to_bytes(64, 'big'))

    secret_key = pow(publickeyclient, private_key, mod)
    print("Secret shared is : ",secret_key,"\n")
     # Convert the key to bytes
    a0 = secret_key.to_bytes(64, byteorder='big') 
    
    k = derive_aes_key(a0)
    #print("Secret key of server:", k)

    c0 = conn.recv(1024)
    c1 = conn.recv(1024)

    if c == 0:
        m0 = aes_decrypt(k, c0)  # Decrypt c0 data when c == 0
        print("Decrypted message m0:", m0)
    else:
        m1 = aes_decrypt(k, c1)  # Decrypt c1 data when c == 1
        print("Decrypted message m1:", m1)

    conn.close()


def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = 'localhost'
    port = 12345
    server_socket.bind((host, port))
    server_socket.listen(1)
    print("Server listening on {}:{}".format(host, port))

    while True:
        conn, addr = server_socket.accept()
        print("Connected to client:", addr)
        exchange_numbers(conn)

run_server()
