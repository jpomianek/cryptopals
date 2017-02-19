#!/usr/local/bin/python3
# Challenge 12: Byte-at-a-time ECB decryption (Simple)

import base64
import pprint
import math
import random
import collections

from Crypto.Cipher import AES

mystery = base64.b64decode(
"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
"YnkK")

randkey = b'\x0b8SS;\xde\xd2@\x9c\\\x15d\n\xfe\x91S'

xor_single_byte_on_array = lambda a, b : [i ^ b for i in a]
hex2bytes = lambda s :[int(s[i:i+2],16) for i in range(0,len(s),2)]
byte_array2string = lambda a : ''.join([chr(i) for i in a])
xor_bytearrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

# Split array a into b sized blocks
arraysplit = lambda a, n : [a[i:i+n] for i in range(0,len(a),n)]

def pkcs7(data):
  l = 16 - (len(data) % 16)
  data += bytes([l])*l
  return data

def aes_ecb_enc(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

def append_mystery_then_aes_ecb(s):
  string = bytes(s,'utf-8') + mystery 
  print(pkcs7(string))
  return aes_ecb_enc(pkcs7(string), randkey)

def aes_ecb_dec(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.decrypt(bytes(data))
  
def aes_cbc_enc(data, key, iv):
  obj = AES.new(key, AES.MODE_ECB)
  prev = iv
  crypted = bytearray()
  for b in arraysplit(data,16):
    xord = xor_arrays(prev,b)
    result = obj.encrypt(bytes(xord))
    crypted += result
    prev = result
  return crypted

def aes_cbc_dec(crypted, key, iv):
  string2byte_array = lambda s: [ ord(i) for i in s ]
  obj = AES.new(key, AES.MODE_ECB)
  decrypted = ''
  prev = string2byte_array(iv)
  for b in arraysplit(crypted, 16):
    a = list(obj.decrypt(b))
    result = xor_arrays(a,prev)
    decrypted += byte_array2string(result)
    prev = b
  return decrypted

def ecb_cbc_detect(ba):
  blocks = arraysplit(ba, 16) 
  uniqblocks = collections.defaultdict(int)
  for b in blocks:
    uniqblocks[str(b)] += 1

  repeats = []
  for l in uniqblocks:
    repeats = list(filter(lambda x: uniqblocks[x] > 1, uniqblocks))

  if (repeats):
    return("ECB")
  else:
    return("CBC")  

# Discover the block size of the cipher
startlen = len(append_mystery_then_aes_ecb('a'))
blocklen = 0
for i in range(2,64):
  enc = append_mystery_then_aes_ecb('a'*i)
  blocklen = len(enc) - startlen
  if (blocklen > 0):
    break

print("Block length is " + str(blocklen) + ".")

# Determine the function used is ECB
mode = ecb_cbc_detect(append_mystery_then_aes_ecb('a'*64))
print("Encryption mode is " + str(mode) + ".")

# Craft an input block that is 1 block short of block size
padlen = 15
pad = 'a'*(padlen)
target = append_mystery_then_aes_ecb(pad)

targetlen = len(append_mystery_then_aes_ecb(''))

matchedblocks = ''

for i in range(0,math.ceil(targetlen/16)):
  matchedthisblock = ''
  for padlen in reversed(range(0,16)):
    pad = 'a'*(padlen)
    target = append_mystery_then_aes_ecb(pad)
    for j in range(0,256):
      attempt = pad + matchedblocks + matchedthisblock + chr(j)
      enc = append_mystery_then_aes_ecb(attempt)
      if enc[17*i:16*(i+1)] == target[17*i:16*(i+1)]:
        matchedthisblock += chr(j)
        break
  matchedblocks += matchedthisblock

print("Decrypt:\n\n" + matchedblocks)
