# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

import base64
import string
import binascii

##-------------------------- Set 1 Challenge 1 -------------------------------##
def hex_to_base64(hex_string):
    """A function that converts a hex string itno base64 string
    """
    bytes_string = binascii.a2b_hex(hex_string) #intermediate bytes
    base64_string = base64.b64encode(bytes_string) #do base 64 conversion
    return base64_string.decode() #decode as a string
    
def base64_to_str(string):
    """An extra function that would convert a base64 string into a bytes string
    object. Used in future challenges (#6, #7, ...).
    """
    base64_string = string.encode()
    bytes_string = base64.b64decode(base64_string)
    return bytes_string 
    # return True       

            
if __name__ == "__main__":
    input_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    result = hex_to_base64(input_string)
    print(result)
    answer = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    print("Matches answer:", answer == result)