# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_7 import*
from crypto_set2_9 import*
from crypto_set2_10 import*

# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
import binascii
import random
import os

##-------------------------- Set 2 Challenge 11 ------------------------------##
def generate_random(n):
    """Generates a n-many random bytes. Can be used 
    for AES key or bytes for appending"""
    return os.urandom(n)

        
def encryption_oracle(input_string):
    """Uses random_encryption function by providing it randomly generated
    AES key and a plaintext padded with random bytes before and after"""
    before = generate_random(random.randint(5,10))
    after = generate_random(random.randint(5,10))
    plaintext = before + input_string + after
    key_AES = generate_random(16)     
    # return  random_encryption(plaintext, key_AES)
    if random.randint(0,1) == 0:
        #50% of the time, we will do CBC
        ciphertext = encrypt_CBC_mode(plaintext, key_AES, generate_random(16))
        print("Actual: CBC")
    else:
        #the other 50% of the time we'll go with ECB
        ciphertext = encrypt_ECB_mode(key_AES, pad_PKSC7(plaintext, 16))
        print("Actual: ECB")
    return ciphertext  
    
def detect_mode(cipher_text):
    """Detects whether the given ciphertext was encrypted using ECB
    or CBC modes, by comparing "potentially" identical blocks
    """
    #We need to find a spot in the text such that blocks match
    block1 = cipher_text[16:32]
    block2 = cipher_text[32:48]
    print((block1))
    print((block2))
    if block1 == block2:
        return "ECB"
    return "CBC"
    

if __name__ == '__main__':
    #Assumption: key size is 16
    # input_string = b"ABCDEFGHIJKLMNOP"*2
    for i in range(5):
        input_string = b"a"*48    
        ciphertext = encryption_oracle(input_string)
        print("My guess:", detect_mode(ciphertext))
        print("----------------------------------------------------")
        