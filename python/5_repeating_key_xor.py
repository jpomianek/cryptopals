#!/usr/local/bin/python3
# Challenge 5: Implement repeating-key XOR

import re

target = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"

str2byte_array = lambda s : [ord(c) for c in s]
byte_array2hexstr = lambda a : ''.join(["{:x}".format(i) for i in a])

xor_byte_arrays = lambda a,b : list(map(lambda x,y: x^y, a,b))

xor_single_byte_on_array = lambda a, b : [i ^ b for i in a]
xor_multibyte_on_array = lambda b_a, a : xor_byte_arrays(a, ((divmod(len(a),len(b_a))[0]+1)*b_a)[0:len(a)])

hex2str = lambda s :''.join(chr(int(s[i:i+2], 16)) for i in range(0, len(s), 2))
bin2str = lambda s : int(s,2).to_bytes((int(s,2).bit_length() + 7) // 8, 'big').decode()

print(byte_array2hexstr(xor_multibyte_on_array(str2byte_array('ICE'), str2byte_array(target))))

