#!/usr/local/bin/python3
# Challenge 14: Byte-at-a-time ECB decryption (Harder)
# "generate a random count of random bytes and prepend this string to
# every plaintext"

import math
import random
import base64
from Crypto.Cipher import AES

mystery = base64.b64decode(
"Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg" +
"aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq" +
"dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg" +
"YnkK")

xor_single_byte_on_array = lambda a, b : [i ^ b for i in a]
hex2bytes = lambda s :[int(s[i:i+2],16) for i in range(0,len(s),2)]
byte_array2string = lambda a : ''.join([chr(i) for i in a])
xor_bytearrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))
arraysplit = lambda a, n : [a[i:i+n] for i in range(0,len(a),n)]

randkey = b'\x0b8SS;\xde\xd2@\x9c\\\x15d\n\xfe\x91S'
randstring = bytes([random.randint(0,255) for i in range(0,random.randint(5,50))])

def pkcs7(data):
  l = 16 - (len(data) % 16)
  data += bytes([l])*l
  return data

def aes_ecb_enc(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

def append_mystery_then_aes_ecb(s):
  string = pkcs7(randstring + bytes(s,'utf-8') + mystery)
  return aes_ecb_enc(string, randkey)

# Discover how many characters we need to add until we're into the next block 
startlen = len(append_mystery_then_aes_ecb(''))
blocklen = 0

arr1 = arraysplit(append_mystery_then_aes_ecb(''),16)
arr2 = arraysplit(append_mystery_then_aes_ecb('a'),16)

i = 0
while (arr1[i] == arr2[i]):
  i += 1

print("First", i , "blocks are stationary (the prepended string is then at least this long)")

#Unknown string occupies at least the first i blocks
initialblockmatches = i

prev = arr2
# If it takes exactly 16 characters for a block to remain stationary,
# we know that the prepended mystery string ended exactly at the end
# of the previous block.
for i in range(2,32):
  cur = arraysplit(append_mystery_then_aes_ecb('a'*i),16)
  if (cur[initialblockmatches] == prev[initialblockmatches]):
    print("After appending",i,"characters, block",initialblockmatches + 1,"is stationary")
    break
  prev = cur

# "Controlled" block: the block we are intentionally filling with
# all "a"s (the character doesn't matter) save for the bytes we're
# interested in identifying

# padlen should be the value that brings the first character
# of our unknown string into the last byte of our controlled
# block
beginpadlen = i + 15

print("beginpadlen:",beginpadlen)

pad = 'a'*(beginpadlen)
targetlen = len(append_mystery_then_aes_ecb('a'*beginpadlen))

matchedblocks = ''
matchedthisblock = ''
for i in range(initialblockmatches + 1,math.ceil(targetlen/16)):
  matchedthisblock = ''
  for padlen in reversed(range(beginpadlen-16,beginpadlen)):
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
