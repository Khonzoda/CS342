# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_1 import*
from crypto_set1_2 import*
from crypto_set1_3 import*
from crypto_set1_5 import*
import binascii
import base64

##-------------------------- Set 1 Challenge 6 -------------------------------##
def hamming_dst_fcn(str1, str2):
    diff = int(binascii.b2a_hex(str1.encode()), 16) ^ \
           int(binascii.b2a_hex(str2.encode()), 16) 
    bin_diff = bin(diff)
    count = 0
    for bit in bin_diff:
       if bit == '1':
            count += 1
    return count


def chunks(l, n):
    """Returns successive n-sized chunks from list l.
    """
    chunks_lst = []
    for i in range(0, len(l), n):
        chunks_lst.append(l[i:i + n])
    return chunks_lst
                                                                        
def transpose_blocks(chunks):
    blocks = []
    keysize = len(chunks[0])
    for i in range(keysize):
        block = ''
        for chunk in chunks:
            if len(chunk) > i:
                block += chunk[i]
        blocks.append(block)           
        
    return blocks
     
        
#Reading in a file               
with open('6.txt') as f:
    base64_text = f.read()        
    
cipher_text = "".join([base64_to_str(line).decode() for line in 
                                                        base64_text.split()])
   
   
#Determine the keysize  
normalized_dsts = []   
for keysize in range(2, 41):
    strings = [cipher_text[:keysize], 
               cipher_text[keysize:2*keysize],
               cipher_text[2*keysize:3*keysize], 
               cipher_text[3*keysize:4*keysize]
              ]
    
    edit_dist1 = hamming_dst_fcn(strings[0], strings[1])
    edit_dist2 = hamming_dst_fcn(strings[0], strings[2])
    edit_dist3 = hamming_dst_fcn(strings[0], strings[3])
    edit_dist4 = hamming_dst_fcn(strings[1], strings[2])
    edit_dist5 = hamming_dst_fcn(strings[1], strings[3])
    edit_dist6 = hamming_dst_fcn(strings[2], strings[3])
    
    avg_edit_dist = sum([edit_dist1, edit_dist2, edit_dist3,
                         edit_dist4, edit_dist5, edit_dist6])/6
    
    normalized_dsts.append((avg_edit_dist/keysize, keysize))

smallest_dst = sorted (normalized_dsts)[:10]
keysize_candidates = [tup[1] for tup in smallest_dst]

# Choose keysize from the list of candidates
keysize = keysize_candidates[0]
# keysize = 29

# Break cipher_text into blocks of keysize
cipher_chunks = chunks(cipher_text, keysize)

#Transpose blocks
transposed = transpose_blocks(cipher_chunks)

#For every transposed block find the best single-byte XOR key
key = b''
for block in transposed:
    key_byte = find_message(binascii.b2a_hex(block.encode()))[0][2]
    key += binascii.a2b_hex(key_byte)
  

#Try decrypting the message with this key
plaintext_hex = repeating_key_XOR(cipher_text, key.decode())
plaintext_bytes = binascii.a2b_hex(plaintext_hex)
plaintext = plaintext_bytes.decode()
           

 
if __name__ == "__main__":
    print("Key found:", key)
    print(plaintext)