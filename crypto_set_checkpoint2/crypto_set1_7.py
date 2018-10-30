# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_1 import*

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import base64

##-------------------------- Set 1 Challenge 7 -------------------------------##
def encrypt_ECB_mode(key, plaintext):
    """Takes a key and plaintext as bytes strings, encrpyts the plaintext 
    using ECB mode, and returns cipher text as a bytes string"""
    #Using the cryptography python package
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor() 
    ciphertext = encryptor.update(plaintext)
    return ciphertext


def decrypt_ECB_mode(key, ciphertext):
    """Takes a key and ciphertext as bytes strings, decrypts the ciphertext 
    using ECB mode, and returns plaintext text as a bytes string"""
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext)
    return plaintext



if __name__ == '__main__':
    #Reading in the file
    with open('7.txt') as f:
        base64_text = f.read()        
               
    #Getting input ready
    cipher_text = b"".join([base64_to_str(line) for line in base64_text.split()])
    
    #Decrypt cipher_text using our key
    key = b"YELLOW SUBMARINE"
    plaintext = decrypt_ECB_mode(key, cipher_text)
    
    print(plaintext.decode())
    
    cipher_text2 = encrypt_ECB_mode(key, plaintext)
    print(cipher_text == cipher_text2)
    
    m = b"Hello world!!!!!"
    k = b"ABCDEFGHIJKLMNOP"
    c = encrypt_ECB_mode(k, m)
    p = decrypt_ECB_mode(k, c)
    
    print("Key:", k)
    print("Message:", m)
    print("Ciphertext:", c)
    print("Plaintext:", p)
    print("Plaintext == Message:", p == m)
    