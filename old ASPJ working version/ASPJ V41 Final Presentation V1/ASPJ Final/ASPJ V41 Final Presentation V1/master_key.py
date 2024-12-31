from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import base64
from Crypto.Hash import SHA512
from cryptography.fernet import Fernet
# Creating a master key
def secret_key_master_key():
    salt = get_random_bytes(32)
    password = 'bx"S.c?@N[%;8Ff#mL6W,('
    master_key = PBKDF2(password, salt, dkLen=32, count=1000000, hmac_hash_module=SHA512)
    with open('nothing.key', 'wb') as f:
        f.write(master_key)
    print(master_key)
def generate_file_encrypt_key():
    key = Fernet.generate_key()
    with open('filekey.key', 'wb') as filekey:
        filekey.write(key)
def encrypt_master_key_file():
    # opening the key
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()
    # using the generated key
    fernet = Fernet(key)
    with open('nothing.key', 'rb') as f:
        original_master_key_file = f.read()
    
    encrypted_file_master_key_file = fernet.encrypt(original_master_key_file)

    with open('nothing.key', 'wb') as ef:
        ef.write(encrypted_file_master_key_file)
def decrypt_master_key_file():
    # opening the key
    with open('filekey.key', 'rb') as filekey:
        key = filekey.read()
    # using the generated key
    fernet = Fernet(key)
    with open('nothing.key', 'rb') as ef:
        encrypted_file_master_key_file = ef.read()

    original_master_key_file = fernet.decrypt(encrypted_file_master_key_file)
    print(original_master_key_file)

# secret_key_master_key()
# generate_file_encrypt_key()
# encrypt_master_key_file()
# decrypt_master_key_file()