import socket
import secrets
from math import gcd
import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def generate_random(min_value, max_value):
    return secrets.randbelow(max_value - min_value + 1) + min_value

def derive_aes_key(shared_secret):
    # Derive an AES-256 key from the shared secret using PBKDF2
    salt = b"salt_for_kdf" 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key size
        salt=salt,
        iterations=100000,  # Recommended number of iterations for PBKDF2
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_secret)
    return aes_key

def modular_inverse(a, m):
    if gcd(a, m) != 1:
        raise ValueError("Modular inverse does not exist.")
    return pow(a, m-2, m)

def pad_message(message):
    padder = padding.PKCS7(128).padder()
    padded_message = padder.update(message) + padder.finalize()
    return padded_message

def aes_encrypt(key, message):
    # Ensure the msg is a multiple of 128 bits
    padded_message = pad_message(message)

    # Generate a random Initialization Vector (IV)
    iv = os.urandom(16)

    # Create an AES cipher instance with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the data
    encryptor = cipher.encryptor()

    # Encrypt the data in chunks
    encrypted_chunks = []
    for i in range(0, len(padded_message), 16):
        chunk = padded_message[i:i+16]
        encrypted_chunks.append(encryptor.update(chunk))

    # Finalize encryption and concatenate encrypted chunks
    encrypted_message = b"".join(encrypted_chunks)
    encrypted_message += encryptor.finalize()

    return iv + encrypted_message

def exchange_numbers():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host = 'localhost'
    port = 12345
    client_socket.connect((host, port))

    mod =  9408805709926587341536627748682697267538057541842091816614276447848922965178961722305792046071437529806027256480806697858153181434361724972502258651588439
    gen = 2
    #print(mod,"\n")
    print("Enter your msg0: ")
    m0 = input()
    m0 = m0.encode('utf-8')
    print('Enter your msg1: ','\n')
    m1 = input()
    m1 = m1.encode('utf-8')

    private_key = generate_random(2, mod - 2)

    public_key = pow(gen, private_key, mod)
    print("Public key sent to server is : ",public_key)
    client_socket.send(public_key.to_bytes(64, 'big'))

    data = client_socket.recv(64)
    server_public_key = int.from_bytes(data, 'big')
    print("Public key received is:", server_public_key,"\n")

    x0 = pow(server_public_key, private_key, mod)
    print("key0 is: ",x0,"\n")
    # Convert the key to bytes
    a0 = x0.to_bytes(64, byteorder='big')
    
    k0 = derive_aes_key(a0)

    inverse_public_key = modular_inverse(public_key, mod)
    k = (inverse_public_key * server_public_key) % mod
    x1 = pow(k, private_key, mod)
    print("key1 is: ",x1,"\n")
    # Convert the key to bytes
    a1 = x1.to_bytes(64, byteorder='big')
    k1 = derive_aes_key(a1)

    #print(k0,"\n")
    #print(k1,"\n")
       

    c0 = aes_encrypt(k0, m0)
    c1 = aes_encrypt(k1, m1)

    client_socket.send(c0)
    client_socket.send(c1)

    client_socket.close()

exchange_numbers()
