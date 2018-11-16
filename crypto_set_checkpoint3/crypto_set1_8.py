# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_6 import chunks

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import base64

##-------------------------- Set 1 Challenge 8 -------------------------------##
#Reading in the file
with open('8.txt') as f:
    hex_lines = [line.strip() for line in f.readlines()]
    
line_blocks = [chunks(line, 32) for line in hex_lines]

#Inspect lines to see how many times their blocks repeat
line_repetitions = []
for i in range(len(line_blocks)):
    blocks_seen = []
    repetitions = 0      
    for block in line_blocks[i]:
        if block not in blocks_seen:
            blocks_seen.append(block)
        else:
            repetitions += 1
    #Append a tuple of repetition count and the line index
    line_repetitions.append((repetitions, i))

    
#Find the line that has the most block repeptitions  
print(sorted(line_repetitions, reverse=True)[:5])
  
  
#The best candidate is line at index 132, since it has 6 repetitions
best_candidate = hex_lines[132]
print(best_candidate)

#Out of curiousity: see which blocks repeat?
block_freq = {}
for block in line_blocks[132]:
    block_freq[block] = block_freq.get(block, 1) + 1

print(block_freq)