# Khonzoda Umarova
# CS 342: Computer Security
# October, 2018

##-------------------------- Set 1 Challenge 2 -------------------------------##        
def fixed_XOR(buf1, buf2):
    """A function that XOR's two hex strings
    """
    int1 = int(buf1, 16) #XOR only works on integers, hence convert it to int
    int2 = int(buf2, 16)
    hex_string = format(int1 ^ int2, 'x') #convert it back to hex
    if len(hex_string)%2 == 1:
        return '0'+ hex_string #odd-length string has zero padding
    else:
        return hex_string

if __name__ == "__main__":
    str1 = "1c0111001f010100061a024b53535009181c"
    str2 = "686974207468652062756c6c277320657965"
    result = fixed_XOR(str1, str2)
    print(result)
    answer = "746865206b696420646f6e277420706c6179"
    print("Matches answer:", answer == result)