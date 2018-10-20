# Khonzoda Umarova
# CS 342: Computer Security
# October 17, 2018

from crypto_set1_1 import*

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import base64

##-------------------------- Set 1 Challenge 7 -------------------------------##
#Reading in the file
with open('7.txt') as f:
    base64_text = f.read()        
    
#Getting input ready
cipher_text = b"".join([base64_to_str(line) for line in base64_text.split()])

#Using the cryptography python package
backend = default_backend()
key = b"YELLOW SUBMARINE"
cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
# encryptor = cipher.encryptor()
# ct = encryptor.update(b"a secret message") + encryptor.finalize()
decryptor = cipher.decryptor()
# print (decryptor.update(cipher_text) + decryptor.finalize())
plaintext = decryptor.update(cipher_text) + decryptor.finalize()


if __name__ == '__main__':
    print(plaintext.decode())
