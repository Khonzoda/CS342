# Khonzoda Umarova
# CS 342: Computer Security
# October 17, 2018

from crypto_set1_2 import*
import binascii

##-------------------------- Set 1 Challenge 5 -------------------------------##
def repeating_key_XOR(plaintext, key):
    """Takes in two strings, one is a plaintext and the other is the key,
    repetitions of which would encrypt the plaintext
    """
    ciphertext = ''
    str_length = len(plaintext)
    key_length = len(key)
    i = 0
    while i < str_length:
        j = 0
        while j < key_length and i < str_length:
            # print plaintext[i], key[j]
            p_hex = binascii.b2a_hex(plaintext[i].encode())
            k_hex = binascii.b2a_hex(key[j].encode())
            c_hex = fixed_XOR(p_hex, k_hex) 
            ciphertext += c_hex   
            i += 1
            j += 1
    return ciphertext 
    
    

if __name__ == "__main__":
    input_string = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    result = repeating_key_XOR(input_string, "ICE")
    print(result)
    answer = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    print("Answer matches:", result == answer)