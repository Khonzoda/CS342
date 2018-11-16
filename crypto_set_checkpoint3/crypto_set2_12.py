# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_1 import*
from crypto_set1_6 import*
from crypto_set1_7 import*
from crypto_set2_9 import*
from crypto_set2_11 import*

# from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
# from cryptography.hazmat.backends import default_backend
import binascii
import random
import os

##-------------------------- Set 2 Challenge 12 ------------------------------##
key_AES = generate_random(16)

def secret_encryption(input_string, key_AES):
    """Modification of oracle from Challenge #11
    """
    # unknown_base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJ"
    unknown_base64 = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
    unknown_string = base64_to_str(unknown_base64)
    plaintext = input_string + unknown_string
    ciphertext = encrypt_ECB_mode(key_AES, pad_PKSC7(plaintext, 16))
    
    return ciphertext 
    
def determine_key_size():
    """Finds the key size for our secret_encryption cipher.
    The logic is:
        1. Here we assume that block size == key size
        2. Ciphertext length is the same size as the plaintext
        3. We use padding (such as PKSC#7) to make sure that resulting plaintext
           has a length that is a multiple of block-size. 
           So adding extra characters to the input string is not going to result
           in proportional increases in the length of ciphertext. However, at 
           some point, one extra byte will tip the the length of ciphertext to 
           the next available size: from kn=(k+1)n, where n is the block size.
        4. The key size cannot be longer than the ciphertext length
    """
    trial_ciphertext = secret_encryption(b"", key_AES)
    for i in range(len(trial_ciphertext)):
        input_string = b"A"*(i+1)
        cipher_text = secret_encryption(input_string, key_AES)
        if len(cipher_text) != len(trial_ciphertext):
            #Calculate key size
            return len(cipher_text) - len(trial_ciphertext)
    #Something weird happened        
    return 0

def determine_ECB(key_size):
    """Checks whether the mode of encryption is ECB or not. Logic is similar 
    to what we did in #11. Returns true, if encryption is ECB, false otherwise 
    """   
    input_string = b"A"*(key_size*2)
    ciphertext = secret_encryption(input_string, key_AES)
    return ciphertext[:key_size] == ciphertext[key_size:2*key_size]
    
def discover_byte(previous_bytes, n, block_num, key_size):
    """Given previous bytes, determines n-th byte in the block_num-th block 
    of the unknown string. Uses logic suggested in the instructions.
    """
    #we feed strings that are between 0-15 bytes long
    short_str = b"A"*(key_size-n)
    #includes one byte from the unknown string
    short_str_cipher = secret_encryption(short_str, key_AES)
    #exhaust all options for the given byte of the unknown string
    for i in range(256):
        byte = bytes([i])
        ciphertext = secret_encryption(short_str+previous_bytes+byte, key_AES)
        #determine which byte this is
        if short_str_cipher[key_size*(block_num-1):key_size*block_num] == \
           ciphertext[key_size*(block_num-1):key_size*block_num]:
            return byte
    #Something went wrong: probably discrepancies due to padding scheme. 
    return None
    
    
def discover_string(block_size):
    """Discovers the whole unknown string block block, byte by byte
    """
    string_so_far = b""
    #Find the size of unknown string (includes padding)
    string_length = len(secret_encryption(b"A"*16, key_AES))
    blocks_num = int(string_length/block_size)
    for i in range(1, blocks_num+1):
        for j in range(1, block_size+1):
            byte = discover_byte(string_so_far, j, i, block_size)
            if byte == None:
                #Quit for loop early if we are in the padding region
                break
            string_so_far += byte
            
    return string_so_far[:-1]
    
    
if __name__ == '__main__':
    key_size = determine_key_size()
    print("Key size", key_size)
    print("Is this ECB mode:", determine_ECB(key_size))
    print("String:")
    print(discover_string(key_size))