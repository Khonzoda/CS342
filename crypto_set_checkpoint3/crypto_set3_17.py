# Khonzoda Umarova
# CS 342: Computer Security
# November, 2018

from crypto_set1_1 import*
from crypto_set1_6 import*
# from crypto_set2_9 import*
from crypto_set2_10 import*
from crypto_set2_11 import*
from crypto_set2_15 import*

import binascii
import random
import os

##-------------------------- Set 3 Challenge 17 ------------------------------##
#global variable for random AES key
secret_key = generate_random(16)
iv = generate_random(16)
#base64_to_str?
strings = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

def encrypt_rand_str():
    '''From the list above selects a random string and encrypts it under CBC 
    mode'''
    #select random string from the list above
    rand_i = random.randint(0,len(strings)-1)
    random_str = strings[rand_i]
    # encrypt the string under CBC
    ciphertext = encrypt_CBC_mode(base64_to_str(random_str), secret_key, iv)
    
    return ciphertext
    

def decrypt_and_check(ciphertext):
    '''Decrypts a given ciphertext and checks its padding
    '''
    plaintext = decrypt_CBC_mode(ciphertext, secret_key, iv)
    # print(plaintext)
    unpadded = unpad_PKCS7(plaintext)
    return unpadded != "BAD padding"


# def find_next_c_byte(c_block, prev_i_bytes): 
#     #this is the padding length and the target_byte
#     n = len(prev_i_bytes)+1
#     prev_c_bytes = [byte^n for byte in prev_i_bytes]
#     for i in range(256):
#         fake_c_block = generate_random(16-n)+bytes([i]+prev_c_bytes)
#         valid = decrypt_and_check(fake_c_block+c_block)
#         if valid:
#             print(i)
#             return i
#     #Something went wrong...
#     raise Exception("Something went wrong")
# 

def find_next_p_byte(prev_c_block, c_block, prev_i_bytes):
    """Given the block of ciphertext we want to decrypt, the previous block
    and intermediate values bytes we have discovered so far, returns the next 
    byte from the plaintext and the byte from intermediate value (that come 
    out of decryption function. Note: all bytes here are treated as integers.
    """
    #First we need to find the ciphertext byte - c_byte
    c_byte = None
    #padding length and target_byte are the same in PKCS#7
    target_byte = len(prev_i_bytes)+1
    prev_c_bytes = [byte^target_byte for byte in prev_i_bytes]
    
    for i in range(256):
        #by iterating through all 256 bytes find an appropriate value for c_byte
        fake_c_block = b'a'*(16-target_byte)+bytes([i]+prev_c_bytes)
        
        #check whether it results in a valid plaintext
        valid = decrypt_and_check(fake_c_block+c_block)
        if valid:
            c_byte = i
    #If something went wrong
    if c_byte == None:
        # print(prev_i_bytes)
        raise Exception("Something went wrong")
     
    #Then we find intermediate value byte - i_byte   
    i_byte = c_byte ^ target_byte
    
    #Lastly, we get the plaintext byte
    p_byte = prev_c_block[-target_byte]^i_byte
    
    return p_byte, i_byte
    
    
def decrypt_block(prev_c_block, c_block):
    '''In order to decrypt a ciphertext block, we take the previous ciphertext
    block and the current one. One after another we recover plaintext bytes
    of this block and accumulate them.
    '''
    p_bytes = []
    i_bytes = []
    for i in range(16):
        # print("p_bytes:", p_bytes)
        tup = find_next_p_byte(prev_c_block, c_block, i_bytes)
        p_bytes.insert(0, tup[0])
        i_bytes.insert(0, tup[1])
    return bytes(p_bytes)
 
 
def decrypt_ciphertext(ciphertext):
     '''Given a ciphertext, breaks it down into chunks of length 16 (keysize).
     Starting from the second chunk decrypts it one by one and returns the
     plaintext.
     '''
     blocks = chunks(ciphertext, 16)
     #we don't know iv, so it is impossible to find the first blocksize of the 
     #text. In order to figure more of the text, we could potentially shrink 
     #the key size, but in real life this is not possible
     plaintext = b'*'*16
     for i in range(1, len(blocks)):
         plaintext += decrypt_block(blocks[i-1], blocks[i])
         
     return plaintext
                      

                        
if __name__ == '__main__':
    """Dear Ada,
    My function works on general. However, from time to time it throws and 
    exception, and I am not sure what is its cause. Every time, a different 
    string fails... I hypothesize this is due to some values of the secret_key 
    or iv. I tried to debug this behavior, but could not find the exact cuase. 
    """
    ciphertext = encrypt_rand_str()
    for string in strings:
        ciphertext = encrypt_CBC_mode(base64_to_str(string), secret_key, iv)
        try:
            we_get = decrypt_ciphertext(ciphertext)
            print("Plaintext string:", decrypt_CBC_mode(ciphertext, secret_key, iv))
            print("What we obtained:", we_get)  
        except:
            print("FAILED:", base64_to_str(string))
        print()
    # ciphertext = encrypt_CBC_mode(base64_to_str("MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="), secret_key, iv)
    # print(decrypt_ciphertext(ciphertext))  
          
