# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

##-------------------------- Set 2 Challenge 9 -------------------------------##
def pad_PKSC7(string, blocksize):
    """Given an input string as bytes and the size of the block, returns
    plaintext padded appropriately using PKCS#7 scheme"""
    length = len(string)
    #if length is a multiple of blocksize, we will pad with blocksize-many bytes
    n = blocksize - length%blocksize
    padding = bytes([n for i in range(n)])
    return string + padding



if __name__ == "__main__":
    input_string = "YELLOW SUBMARINE"
    block_size = 8
    print("input_string=", input_string)
    print("block_size=", block_size)
    print(pad_PKSC7(input_string.encode(), block_size))
    print("--------------------------------------------")
    block_size = 25
    print("input_string=", input_string)
    print("block_size=", block_size)
    print(pad_PKSC7(input_string.encode(), block_size))
    print("--------------------------------------------")
    block_size = 16
    print("input_string=", input_string)
    print("block_size=", block_size)
    print(pad_PKSC7(input_string.encode(), block_size))
    
    
    