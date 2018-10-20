# Khonzoda Umarova
# CS 342: Computer Security
# October 17, 2018

from crypto_set1_3 import*
import binascii

##-------------------------- Set 1 Challenge 4 -------------------------------##
#Read the file 
with open("4.txt", "r") as f:
    lines = [line.strip() for line in f.readlines()]
     
#try decrypting every line to get candidates
all_candidates = []
for line in lines:
    line_candidates = find_message(line)
    all_candidates += [(tup[0],tup[1],tup[2],line) for tup in line_candidates]

if __name__ == "__main__":
    #candidates list contains tuples with score, plaintext, and the cyphertext
    best_candidates = sorted(all_candidates, reverse=True)[:20]
    # print best_candidates
    print(best_candidates[0])