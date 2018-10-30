# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_1 import*
from crypto_set1_2 import*
from crypto_set1_6 import*
from crypto_set1_7 import*
from crypto_set2_9 import*

import binascii

##-------------------------- Set 2 Challenge 10 ------------------------------##
def pad_zeros(string, block_size):
    """Given a string and a block size, adds zeros to the beginning,
    and returns a string of the same length as the block size
    """
    n = block_size - len(string)
    padding = bytes([0 for i in range(n)])
    return padding+string
    

def encrypt_CBC_mode(plaintext, key, iv):
    """Takes plaintext, key, and iv as bytes stirngs, pads the plaintext
    using PKSC#7 appropriately and encrypts it using CBC mode
    """
    block_size = len(key)
    padded_plaintext = pad_PKSC7(plaintext, block_size)
    blocks = chunks(padded_plaintext, block_size)
    cipher_text = b""
    current_iv = iv
    for block in blocks:
        #first we xor the block of plaintext with previous cipherblock
        xor_result = fixed_XOR(binascii.b2a_hex(current_iv), 
                                 binascii.b2a_hex(block))                       
        intermediate = pad_zeros(binascii.a2b_hex(xor_result), block_size)
        # print(len(intermediate))
        # print(len(block))
        # print(binascii.b2a_hex(current_iv).decode())
        # print(binascii.b2a_hex(block).decode())
        #Then XOR this intermediate value with the key                         
        cipher_block = encrypt_ECB_mode(key, intermediate)
        
        current_iv = cipher_block
        cipher_text += cipher_block
        
    return cipher_text
        

def decrypt_CBC_mode(ciphertext, key, iv):
    """Takes ciphertext, key, and iv as bytes stirngs and decrypts 
    the ciphertext using key and iv provided using CBC mode
    """
    block_size = len(key)
    blocks = chunks(ciphertext, block_size)
    plaintext = b""
    current_iv = iv
    for block in blocks:
        intermediate = decrypt_ECB_mode(key, block)
        plain_block_hex = fixed_XOR(binascii.b2a_hex(current_iv), 
                                    binascii.b2a_hex(intermediate))
        plain_block = binascii.a2b_hex(plain_block_hex)
        
        plaintext += plain_block
        current_iv = block
        
    return plaintext

def read_base64_ciphertext(filename):    
    """Given a filename, reads a file that contains cyphertext in base64, 
    returns a ciphertext as a bytes string"""           
    with open(filename) as f:
        base64_text = f.read()      
    one_line = base64_text.split()    
    ciphertext = base64_to_str(base64_text)
    return ciphertext
    
    
    
if __name__ == "__main__":
    ciphertext = read_base64_ciphertext('10.txt')
    # print(ciphertext)
    key = b"YELLOW SUBMARINE"
    iv = bytes([0 for i in range(len(key))])
    plain_text = decrypt_CBC_mode(ciphertext, key, iv)
    # print(plain_text.decode())
    
    m = b"Hello world!! This is Khonzoda coding..."
    # k = b"ABCDEFGHIJKLMNOP"
    k = b"YELLOW SUBMARINE"
    iv = bytes([0 for i in range(len(k))])
    c = encrypt_CBC_mode(m, k, iv)
    p = decrypt_CBC_mode(c, k, iv)
    
    print("Key:", k)
    print("Message:", m)
    print("Message padded:", pad_PKSC7(m, 16))
    print("Ciphertext:", c)
    print("Plaintext:", p)
    print("Plaintext == Message padded:", p == pad_PKSC7(m, 16))
    
