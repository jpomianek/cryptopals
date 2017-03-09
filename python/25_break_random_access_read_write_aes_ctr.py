#!/usr/local/bin/python3

import base64
import struct
from Crypto.Cipher import AES
from collections import defaultdict 
from os.path import isfile

splitbytes = lambda a,b : [a[i:i+b] for i in range(0,len(a),b)]
xor_bytearrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

def aes_ecb_dec(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.decrypt(bytes(data))

def aes_ecb_enc(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

def aes_ctr(string,key,nonce):
  arr = splitbytes(string,16)
  result = bytearray()
  for count in range(0,len(arr)):
    out = aes_ecb_enc(struct.pack('ll',nonce,count),key)
    out = out[:len(arr[count])]
    result += xor_bytearrays(arr[count],out)
  return result

def edit_ctr(ciphertext,key,offset,newtext):
  nonce = 0
  arr = splitbytes(ciphertext,16)     
  print("arr0:", arr[0])
  startblock = int(offset/16) * 16
  endblock = int((offset+len(newtext))/16) + 1
  print("startblock:",startblock,"endblock:",endblock)
  dec = bytes() 
  # decrypt affected blocks
  for count in range(startblock,endblock):
    enc = aes_ecb_enc(struct.pack('ll',nonce,count),key)
    enc = enc[:len(arr[count])]
    dec += xor_bytearrays(arr[count],enc)

  print("arr0:", arr[0])
  # splice in our substitution text
  dec = dec[0:offset] + bytes(newtext,'utf-8') + dec[offset + len(newtext):]
  dec_split = splitbytes(dec,16)
  print("dec0:",dec_split[0])

  # re-encrypt
  for count in range(startblock,endblock):
    enc = aes_ecb_enc(struct.pack('ll',nonce,count),key)
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

ct_ctr = aes_ctr(plaintext,key,0)

edited = edit_ctr(ct_ctr,key,5,'blal')
print(edited)
