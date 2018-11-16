# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

from crypto_set1_2 import*
import string
import binascii

##-------------------------- Set 1 Challenge 3 -------------------------------## 
def find_message(hex_string):
    """Given a list of candidates, applies scoring function to determine the
    most likely plaintext. Results are returned in the form of a list of tuples, 
    sorted in decreasing order, where each tuple contains score and 
    corresponding plaintext
    """
    #get all possible candidates
    candidates = find_candidates(hex_string)
    #apply scoring function to each one of them
    score_tups = sorted([(score_plaintext(tup[0]), tup[0], tup[1]) for tup in candidates],
                        reverse=True)
    return score_tups

      
##-----Helper functions-----##  
def find_candidates(hex_string):
    """Given a hex string returns a list of possible plaintext candidates
    in bytes
    """
    candidates = [] 
    #Try to use every 1 byte character (between 0x00 and 0xFF) as a key  
    characters = ['00', '01', '02', '03', '04', '05', '06', '07', \
                  '08', '09', '0a', '0b', '0c', '0d', '0e', '0f'] + \
                  [format(char, 'x') for char in range(16, 256)]
    for letter in characters:
        #generate plaintext candidates
        candidates.append((decrypt_ciphertext(hex_string, letter.encode()), 
                           letter.encode())
                         )
    return candidates

def decrypt_ciphertext(hex_string, hex_key):
    """Provided a hex_string and a key (in hex), decript the hex_string 
    to retutn a plaintext in a form of bytes
    """
    length = int(len(hex_string)/2) #twice as less as the hex representation
    stretch = hex_key*length #create a string by repeating key character
    message = fixed_XOR(hex_string, stretch) # get the message
    #format message as bytes string
    return binascii.a2b_hex(message)
    
    
def count_letters(plaintext):
    """Given a plaintext in ascii, counts how many of each chars it has. Returns
    results in the form of a dictionary, where keys are distinct characters and 
    values are number of times the character has been repeated
    """
    frequencies = {}
    for letter in plaintext:
        frequencies[bytes([letter])] = frequencies.get(bytes([letter]), 0) + 1
    return frequencies
    
    
def score_plaintext(plaintext):
    """Given a plaintext, assings the score that indicates the likelihood of the
    plaintext being in English. The function considers the frequency of 
    different letters in the alphabet; common puncuation is zeroed; all other
    non-alpha characters are counted against the score
    """
    english_freq = {b'e':12.702, b't':9.056, b'a':8.167, b'o':7.507, b'i':6.966,
                    b'n':6.749, b's':6.327, b'h':6.094, b'r':5.987, b'd':4.253, 
                    b'l':4.025, b'c':2.782, b'u':2.758, b'm':2.406, b'w':2.360, 
                    b'f':2.228, b'g':2.015, b'y':1.974, b'p':1.929, b'b':1.492, 
                    b'v':0.978, b'k':0.772, b'j':0.153, b'x':0.150, b'q':0.095, 
                    b'z':0.074, 
                    b'E':12.702, b'T':9.056, b'A':8.167, b'O':7.507, b'I':6.966,
                    b'N':6.749, b'S':6.327, b'H':6.094, b'R':5.987, b'D':4.253, 
                    b'L':4.025, b'C':2.782, b'U':2.758, b'M':2.406, b'W':2.360, 
                    b'F':2.228, b'G':2.015, b'Y':1.974, b'P':1.929, b'B':1.492, 
                    b'V':0.978, b'K':0.772, b'J':0.153, b'X':0.150, b'Q':0.095, 
                    b'Z':0.074, 
                    b' ':13, b'.':0.017, b',':0, b'!':0, b'?':0, b"'":0.075}     
    text_freq = count_letters(plaintext)
    # length = len(plaintext)
    score = 0
    for item in text_freq:
        score += english_freq.get(item, -13)*text_freq[item]   
    return round(score, 2)
   



if __name__ == "__main__":
    input_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    # print(find_message(input_string)[:10])
    print(find_message(input_string)[0])