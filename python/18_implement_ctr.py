#!/usr/local/bin/python3
# Challenge 18: Implement CTR, the stream cipher mode

import base64
import struct
from Crypto.Cipher import AES

arraysplit = lambda a, b : [a[i:i+b] for i in range(0,len(a),b)]
xor_bytearrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

ct = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

def aes_ecb_enc(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

def aes_ctr(string,key,nonce):
  arr = arraysplit(string,16)
  result = bytearray()
  for count in range(0,len(arr)):
    out = aes_ecb_enc(struct.pack('ll',nonce,count),key)
    out = out[:len(arr[count])]
    result += xor_bytearrays(arr[count],out)
  return result

print("Decrypted:", aes_ctr(base64.b64decode(ct),'YELLOW SUBMARINE',0).decode('utf-8'))
