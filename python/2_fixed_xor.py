#!/usr/local/bin/python3
# Challenge 2: Take two equal-length buffers and produce their XOR combination.

def hexxor(a, b):
    """Take two equal-length hexidecimal buffers and return their XOR combination"""
    hex2bin = lambda s : "".join(["{0:04b}".format(int(c, 16)) for c in s])
    bin2hex = lambda b : "{:x}".format(int(b,2)) 

    bin_s =  "".join(list(map(lambda x,y: str(int(x) ^ int(y)), hex2bin(a), hex2bin(b))))
    
    return bin2hex(bin_s)

a = "1c0111001f010100061a024b53535009181c"
b = "686974207468652062756c6c277320657965"
print(a + " xor'd with\n" + b + ":\n" + '-'*36 + "\n" + hexxor(a,b))
