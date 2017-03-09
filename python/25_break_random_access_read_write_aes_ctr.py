#!/usr/local/bin/python3

import base64
import struct
from Crypto.Cipher import AES
from collections import defaultdict 
from os.path import isfile

splitbytes = lambda a,b : [a[i:i+b] for i in range(0,len(a),b)]
xor_bytearrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

stored_key = 'super$$$$randomm'

def aes_ecb_dec(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.decrypt(bytes(data))

def aes_ecb_enc(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

def aes_ctr(string,nonce):
  arr = splitbytes(string,16)
  result = bytearray()
  for count in range(0,len(arr)):
    out = aes_ecb_enc(struct.pack('ll',nonce,count),stored_key)
    out = out[:len(arr[count])]
    result += xor_bytearrays(arr[count],out)
  return result

def edit_ctr(ciphertext,offset,newtext):
  nonce = 0
  arr = splitbytes(ciphertext,16)     
  startblock = int(offset/16) * 16
  endblock = int((offset+len(newtext))/16) + 1
  dec = bytes() 
  # decrypt affected blocks
  for count in range(startblock,endblock):
    enc = aes_ecb_enc(struct.pack('ll',nonce,count),stored_key)
    enc = enc[:len(arr[count])]
    dec += xor_bytearrays(arr[count],enc)
  # splice in our substitution text
  dec = dec[:offset] + bytes(newtext,'utf-8') + dec[offset + len(newtext):]
  dec_split = splitbytes(dec,16)

  # re-encrypt
  for count in range(startblock,endblock):
    enc = aes_ecb_enc(struct.pack('ll',nonce,count),stored_key)
    enc = enc[:len(arr[count])]
    arr[count] = xor_bytearrays(dec_split[count],enc)
  
  return b"".join(arr)

if not isfile('25.txt'):
  print('25.txt not found. Quitting.')
  quit()

with open('25.txt') as f:
  lines = [x.strip('\n') for x in f.readlines()]

key = 'YELLOW SUBMARINE'
ciphertext = base64.b64decode(''.join(lines))

plaintext = aes_ecb_dec(ciphertext, key)
original_crypted = aes_ctr(plaintext,0)

for d in range(0,16):
  for i in range(0,128):
    edited = edit_ctr(original_crypted,d,chr(i))
    if original_crypted[d] == edited[d]:
      print(chr(i), end="")

print()
#  print(edited[0])
