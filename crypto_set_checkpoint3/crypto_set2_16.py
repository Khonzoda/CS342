# Khonzoda Umarova
# CS 342: Computer Security
# November, 2018

from crypto_set2_9 import*
from crypto_set2_10 import*
from crypto_set2_11 import*
from crypto_set2_15 import*

import random
import os

##-------------------------- Set 2 Challenge 16 ------------------------------##
prepend_str = b"comment1=cooking%20MCs;userdata="
append_str = b";comment2=%20like%20a%20pound%20of%20bacon"
random_key = generate_random(16)
iv = generate_random(16)

def encrypt_data(user_input):
    quoted = user_input
    # quoted = user_input.replace(b"=",b"").replace(b";",b"")
    plaintext = prepend_str + quoted + append_str
    #no need to pad since encrypt_CBC_mode function already pads the plaintext
    ciphertext = encrypt_CBC_mode(plaintext, random_key, iv)
    return ciphertext
    

def decrypt_data(ciphertext):
    plaintext = decrypt_CBC_mode(ciphertext, random_key, iv)
    string = unpad_PKCS7(plaintext)
    print("Plaintext:" ,string)
    return b";admin=true;" in string
    

def bit_flip(ciphertext, k):
    """A function that flips the necessary bits in the kth block of the
    ciphertext and returns the updated ciphertext.
    Here we are told to assume that the block size is 16
    """
    target_bytes = [0, 6, 11, 13]
    block = ciphertext[16*(k-1):16*k]
    new_block = bytes([])
    for i in range(16):
        if i in target_bytes:
            #XORing with 1 achieves a flip of the least significant bit
            new_block += bytes([block[i]^1])
        else:
            new_block += bytes([block[i]])
    
    new_ciphertext = ciphertext[:16*(k-1)] + new_block + ciphertext[16*k:]
    return new_ciphertext

#convert bytes into hex str 


def evil():
    user_input = b"AAAAAAAAAAAAAAAA:admin<true:A<AA"
    ciphertext = encrypt_data(user_input)
    #ciphertext is now in the posession of Evil
    modified_ciphertext = bit_flip(ciphertext, 3)
    plaintext = decrypt_data(modified_ciphertext)
    return plaintext
        
if __name__ == '__main__':
    #testing
    print("The user is admin:", evil())
    