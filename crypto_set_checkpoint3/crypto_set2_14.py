# Khonzoda Umarova
# CS 342: Computer Security
# November, 2018

import binascii
import random
import os

from crypto_set1_1 import*
from crypto_set1_6 import*
from crypto_set1_7 import*
from crypto_set2_9 import*
from crypto_set2_11 import*

##-------------------------- Set 2 Challenge 14 ------------------------------##
random_prefix = generate_random(random.randint(1, 128))
# random_prefix = b"\x93)\xf9\xe3\x0fb\xfb\x12(\n\xbf\x8f4\x97\xb9\x91\x80\xfa\x1c\xa7r\xc8(\x97\x8fa3\xdf\x14\x9ev\xda\xf2\xdc\xb1]\xc4\xc9\xc5\x8c|N\xc5'V\xc2\xc8\xec\xfc\xe4\x8d\xc4S3\x04\xcd=\x8a\x99|\xbby\xfd\xf5\x1dR\x05\x08\x1a\x1b\x00\xe0K\x12u\xa3\xdab\xcc\xfd0\x88?%"
# random_prefix = b"\xec\x80s\x1d\xa6E\xaabM"
key_AES = generate_random(16)
target_bytes = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"

def secret_encryption(input_string, key_AES):
    """Modification of secret_encryption from Challenge #12 with addition
    of random prefix
    """
    unknown_string = base64_to_str(target_bytes)
    # unknown_string = b"\x01\x02\x03\x04"
    # unknown_string = b"Yellow submarine\x10"
    plaintext = random_prefix + input_string + unknown_string
    ciphertext = encrypt_ECB_mode(key_AES, pad_PKSC7(plaintext, 16))
    
    return ciphertext 
    
def determine_key_size():
    """Modification of determine_key_size from Challenge #12 with addition
    of random prefix
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
    """Modification of determine_key_size from Challenge #12 with addition
    of random prefix 
    """    
    input_string = b"A"*(key_size*3)
    ciphertext = secret_encryption(input_string, key_AES)
    blocks = chunks(ciphertext, key_size)
    prev_block = blocks[0]
    for block in blocks[1:]:
        if block == prev_block:
            return True
        prev_block = block
    return False
 
def determine_prefix_length(key_size):
    """Helper function that determines the length of the random prefix, as
    the third element of an output tuple. The first tuple element is the first 
    block after prefix string ends, and the second element is the padding to
    make prefix string mod key_size
    """
    for i in range(1, key_size+1):
        input_string = b"B"*i + b"A"*(key_size*2)
        ciphertext = secret_encryption(input_string, key_AES)
        blocks = chunks(ciphertext, key_size)
        for j in range(1, len(blocks)):
            if blocks[j] == blocks[j-1]:
                return j, i, (j-1)*key_size - i
    #Something went wrong
    return 0
            
def discover_byte(previous_bytes, n, block_num, key_size, padding):
    """Given previous bytes, determines n-th byte in the block_num-th block 
    of the unknown string. Uses logic suggested in the instructions.
    """
    #we feed strings that are between 0-15 bytes long
    short_str = padding + b"A"*(key_size-n)
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
    tup = determine_prefix_length(key_size)
    start_block = tup[0]
    pad_size = tup[1]
    padding = b"B"*pad_size
    
    string_so_far = b""
    #Find the size of unknown string (includes padding)
    string_length = len(secret_encryption(b"A"*32, key_AES))
    blocks_num = int(string_length/block_size)
    for i in range(start_block, blocks_num+1):
        for j in range(1, block_size+1):
            byte = discover_byte(string_so_far, j, i, block_size, padding)
            if byte == None:
                #Quit for loop early if we are in the padding region
                break
            string_so_far += byte
            
    return string_so_far[:-1]


if __name__ == '__main__':
    key_size = determine_key_size()
    print("Key size", key_size)
    print("Is this ECB mode:", determine_ECB(key_size))
    print("Prefix length:", determine_prefix_length(key_size)[2])
    print("String:")
    print(discover_string(key_size))