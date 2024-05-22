import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class SSHCrypto:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_key_pair(self):
        key = paramiko.RSAKey.generate(2048)
        self.private_key = key
        self.public_key = key.get_base64()

    def save_private_key(self, filename, password=None):
        self.private_key.write_private_key_file(filename, password=password)

    def save_public_key(self, filename):
        with open(filename, 'w') as f:
            f.write(f"{self.public_key}\n")

    def load_private_key(self, filename, password=None):
        self.private_key = paramiko.RSAKey(filename=filename, password=password)

    def encrypt_file(self, input_filename, output_filename):
        if not self.public_key:
            raise ValueError("Can't find public key")
        with open(input_filename, 'rb') as f:
            data = f.read()
        public_key = serialization.load_ssh_public_key(
            f"ssh-rsa {self.public_key}".encode(),
            backend=default_backend()
        )
        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(output_filename, 'wb') as f:
            f.write(encrypted_data)

    def decrypt_file(self, input_filename, output_filename):
        if not self.private_key:
            raise ValueError("Private key is not loaded.")
        with open(input_filename, 'rb') as f:
            encrypted_data = f.read()
        private_key = self.private_key.key
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        with open(output_filename, 'wb') as f:
            f.write(decrypted_data)

crypto = SSHCrypto()
private_key_location = './temp/private_key.pem'
public_key_location = './temp/public_key.pem'

password = input("Enter your private key password :\n")

crypto.generate_key_pair()
crypto.save_private_key(private_key_location, password)
crypto.save_public_key(public_key_location)

crypto.load_private_key(private_key_location, password)
crypto.encrypt_file('plain_text.txt', 'encrypted_data.bin')
crypto.decrypt_file('encrypted_data.bin', 'decrypted_text.txt')
