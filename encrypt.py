from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from getpass import getpass


def encrypt_to_file(output_filename:str, salt_filename:str, message:str):

    key = get_key(salt_filename)    
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_data = cipher.encrypt(pad(message.encode(), AES.block_size))

    with open(output_filename, "wb") as f:
        f.write(cipher.iv)
        f.write(cipher_data)

def decrypt_from_file(input_filename:str, salt_filename:str):

    with open(input_filename, "rb") as f:
        iv = f.read(16)
        decrypt_data = f.read()

    key = get_key(salt_filename)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    plain_data = unpad(cipher.decrypt(decrypt_data), AES.block_size)

    return plain_data.decode()


def get_key(salt_filename):

    with open(salt_filename, "rb") as f:
        salt = f.read()

    password = getpass("Password: ")

    return PBKDF2(password, salt, dkLen=32)

salt_filename = "salt.bin"
# url = encrypt_to_file("url.bin", salt_filename, "192.168.0.1")
url = decrypt_from_file("url.bin", salt_filename)
print(url)
