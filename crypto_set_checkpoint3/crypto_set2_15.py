# Khonzoda Umarova
# CS 342: Computer Security
# November, 2018

from crypto_set2_9 import*

import binascii
import random
import os

##-------------------------- Set 2 Challenge 15 ------------------------------##
def unpad_PKCS7(plaintext,BLOCKSIZE=16):
    #print(plaintext)
    remainder = len(plaintext) % BLOCKSIZE
    if remainder != 0:
        return "BAD padding"
        
    for i in range(1, BLOCKSIZE+1):
        byte = bytes([i])
        last_n_bytes = plaintext[-i:]
        if last_n_bytes == byte*i:
            return plaintext[:-i]
    return "BAD padding"
   
    
if __name__ == '__main__':
    #testing
    print("Plaintext: ", b"ICE ICE BABY\x01\x02\x03\x04")
    print(unpad_PKCS7(b"ICE ICE BABY\x01\x02\x03\x04",16))
    print()
    print("Plaintext: ", b"ICE ICE BABY\x05\x05\x05\x05")
    print(unpad_PKCS7(b"ICE ICE BABY\x05\x05\x05\x05",16))
    print()
    print("Plaintext: ", b"ICE ICE BABY\x04\x04\x04\x04")
    print(unpad_PKCS7(b"ICE ICE BABY\x04\x04\x04\x04",16))
    
