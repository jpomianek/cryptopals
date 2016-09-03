#!/usr/local/bin/python3

# Challenge 3: Break single-byte XOR cipher

import re

encoded = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

hex2bin = lambda s : "".join(["{0:04b}".format(int(c, 16)) for c in s])
bin2hex = lambda b : "{:x}".format(int(b,2))
xor_hex = lambda a, b :  bin2hex("".join(
                          list(map(
                          lambda x,y: 
                            str(int(x) ^ int(y)), hex2bin(a), hex2bin(b)
                            ))))

xor_w_byte = lambda s, b : xor_hex(s, b*len(s))
hex2str = lambda s :''.join(
                        chr(int(s[i:i+2], 16)) for i in range(0, len(s), 2))
bin2str = lambda s : int(s,2).to_bytes(
                      (int(s,2).bit_length() + 7) // 8, 'big'
                      ).decode()

freq = {} 

for i in range(0,256):
    s = hex2str(xor_w_byte(encoded, "{:x}".format(i)))
    freq[i] = len(re.findall("[ETAOIN SHRDLU]", s, re.IGNORECASE))

print("XOR Byte, Count, Decrypt")

for i in sorted(freq, key=freq.__getitem__, reverse=True)[0:1]:
    print(str(i) + ", " 
        + str(freq[i]) 
        + ", " + hex2str(xor_w_byte(encoded,"{:x}".format(i))))
