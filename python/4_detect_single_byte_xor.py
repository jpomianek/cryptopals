#!/usr/local/bin/python3
# Challenge 4: Detect single-character XOR

import re

with open('4.txt') as f:
    lines = [x.strip('\n') for x in f.readlines()]

hex2bin = lambda s : "".join(["{0:04b}".format(int(c, 16)) for c in s])
bin2hex = lambda b : "{:x}".format(int(b,2))
xor_hex = lambda a, b :  bin2hex("".join(list(map(lambda x,y: str(int(x) ^ int(y)), hex2bin(a), hex2bin(b)))))
xor_w_byte = lambda s, b : xor_hex(s, b*len(s))

hex2str = lambda s :''.join(chr(int(s[i:i+2], 16)) for i in range(0, len(s), 2))

print("\nHex string, \"ETAOIN SHRDLU\" frequency\n")
linefreq = {}
bestbyte = {}

for l in lines:
    freq = {} 
    # Try xor-ing against all possible byte values, keeping a tally of
    # matches in character class [etoain shrdlu] in each resulting
    # string
    for i in range(0,256):
        s = hex2str(xor_w_byte(l, "{:x}".format(i)))
        freq[i] = len(re.findall("[ETAOIN SHRDLU]", s, re.IGNORECASE))
    linefreq[l] = max(freq.values()) 
    bestbyte[l] = max(freq, key=freq.get)
    print(l + " " + str(max(freq.values())))

print("\n\n\nBest guess:\nHex string, \"ETAOIN SHRDLU\" frequency, Decrypted")

for i in sorted(linefreq, key=linefreq.__getitem__, reverse=True)[0:1]:
    print(str(i) + ", " 
          + str(linefreq[i]) + ", " 
          + hex2str(xor_w_byte(i,"{:x}".format(bestbyte[i]))
            ))
