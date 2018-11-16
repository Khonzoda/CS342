# Khonzoda Umarova
# CS 342: Computer Security
# November, 2018

from crypto_set1_7 import*
from crypto_set2_11 import*
from crypto_set2_15 import*

import binascii
import random
import os

##-------------------------- Set 2 Challenge 13 ------------------------------##
key_AES = generate_random(16)


def parse_cookie(cookie):
    cookie_dct = {}
    key_val_pairs = cookie.split("&")
    for pair in key_val_pairs:
        key, value = pair.split("=")[0], pair.split("=")[1]
        cookie_dct[key] = value
    return cookie_dct
    
    
def encode_cookie(cookie_dct):
    cookie_lst = []
    for key in cookie_dct:
        cookie_lst.append(key + "=" + cookie_dct[key])
    return "&".join(cookie_lst)    
 
           
def profile_for(email_addr):
    if "&" in email_addr or "=" in email_addr:
        print("Invalid email address")
        return None 
    return "email={}&uid=10&role=user".format(email_addr)  
    
      
def encrypt_profile(profile, BLOCKSIZE=16):
    return encrypt_ECB_mode(key_AES, pad_PKSC7(profile.encode(), BLOCKSIZE))
  
      
def decrypt_profile(ciphertext):
    cookie = decrypt_ECB_mode(key_AES, ciphertext)
    unpad = unpad_PKCS7(cookie) #get rid of padding
    return parse_cookie(unpad.decode())

          
def cut_and_paste(email, BLOCKSIZE=16):
    # Get the first part of ciphertext - where we have email & uid
    pad = BLOCKSIZE - (len("email=&uid=10&role=")+len(email))%BLOCKSIZE
    padded_email1 = email + " "*pad
    profile1 = profile_for(padded_email1)
    # Produce corresponding ciphertext
    ciphertext1 = encrypt_profile(profile1)  
    part1 = ciphertext1[:-BLOCKSIZE]
     
    # Get the second part of ciphertext - where we have admin as a role
    padded_email2 = " "*10 + "admin" + '\x0b'*11
    profile2 = profile_for(padded_email2)
    ciphertext2 = encrypt_profile(profile2)  
    part2 = ciphertext2[BLOCKSIZE:2*BLOCKSIZE]
    
    return part1 + part2
                          
                            
                                
if __name__ == '__main__':
    email = "foo@bar.com"
    profile = profile_for(email)
    cipher_profile = encrypt_profile(profile)
    cut_n_paste = cut_and_paste(email)
    print("Email:", email)
    print("Original:", decrypt_profile(cipher_profile))
    print("Cut&Paste:", decrypt_profile(cut_n_paste))
    
    print("------------------------------------------------")
    
    email = "ivan_sergeyevich_petrov@vzlom.ru"
    profile = profile_for(email)
    cipher_profile = encrypt_profile(profile)
    cut_n_paste = cut_and_paste(email)
    print("Email:", email)
    print("Original:", decrypt_profile(cipher_profile))
    print("Cut&Paste:", decrypt_profile(cut_n_paste))
    
    