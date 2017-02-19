#!/usr/local/bin/python3
# Challenge 17: The CBC padding oracle
# Use knowledge about PKCS#7 padding errors in decrypting to decrypt a
# ciphertext

import random
import base64

from Crypto.Cipher import AES
random.seed()

arraysplit = lambda a, b : [a[i:i+b] for i in range(0,len(a),b)]
xor_arrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

randstrings = [
"MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93" ]

randkey = bytes([random.randint(0,255) for i in range(0,16)])
#Needs to be mutable for this experiment
randiv = bytearray(bytes([random.randint(0,255) for i in range(0,16)]))

def pkcs7(data):
  l = 16 - (len(data) % 16)
  data += bytes([l])*l
  return data

def pkcs7_validate(data):
  padlen = data[-1]
  if not (0 < padlen < 17):
    raise ValueError("Invalid PKCS7 padding detected")
  if (len(data) % 16):
    raise ValueError("String length must be multiple of 16")
  p = 1
  for i in reversed(data):
    if i != padlen and p <= padlen:
      raise ValueError("Invalid PKCS7 padding detected")
    if p == padlen:
      break
    p += 1
  return data[:-padlen]

def aes_cbc_enc(data, key, iv):
  obj = AES.new(key, AES.MODE_ECB)
  prev = iv
  crypted = bytearray()
  for b in arraysplit(bytes(data),16):
    xord = xor_arrays(prev,b)
    result = obj.encrypt(xord)
    crypted += result
    prev = result
  return crypted

def aes_cbc_dec(crypted, key, iv):
  obj = AES.new(key, AES.MODE_ECB)
  decrypted = bytearray()
  prev = iv
  for b in arraysplit(crypted, 16):
    a = obj.decrypt(bytes(b))
    result = xor_arrays(a,prev)
    decrypted += result
    prev = b
  return decrypted

def select_and_encrypt():
  choice = random.randint(0,len(randstrings)-1)
  padded = pkcs7(base64.b64decode(randstrings[choice]))
  return aes_cbc_enc(padded, randkey, randiv) 

def decrypt_and_pkcs7_validate(data):
  plaintext = aes_cbc_dec(data,randkey,randiv)
  pkcs7_validate(plaintext)

matched = bytearray()
ct = select_and_encrypt()
print(ct)
orig = ct.copy()
while (len(ct) > 16):
  target = len(ct) - 17
  for i in range(1,17):
    matches = []
    original = ct[target]
    print("Original byte at " + str(target) + ": " + str(original))
    for c in range(0,256):
      ct[target] = c
      try:
        decrypt_and_pkcs7_validate(ct)
      except ValueError:
        continue
      else:
        matches.append(c)
        print("Whoa, no padding error with byte =", c)
    if(len(matches)>1):
      matches.remove(original)
    matchval = matches[0] ^ i ^ original
    print(matches[0],"^",i,"^",original,"=",matchval,":",chr(matchval))
    matched = bytearray([matches[0] ^ i ^ original]) + matched
    # Set up for the next byte 
    ct[target]= matches[0] ^ i ^ (i + 1)
    for j in range(1,i):
      ct[target + j] = ct[target + j] ^ i ^ (i + 1)
    target -= 1
  # Trim 16 bytes off the end and start anew
  orig = orig[:-16]
  ct = orig.copy()

# Now twiddle with the iv to find the last block of plaintext 
target = 15
for i in range(1,17):
  matches = []
  original = randiv[target]
  print("Original byte at " + str(target) + ": " + str(original))
  for c in range(0,256):
    randiv[target] = c
    try:
      decrypt_and_pkcs7_validate(ct)
    except ValueError:
      continue
    else:
      matches.append(c)
      print("Whoa, no padding error with byte =", c)
  if(len(matches)>1):
    matches.remove(original)
  matchval = matches[0] ^ i ^ original
  print(matches[0],"^",i,"^",original,"=",matchval,":",chr(matchval))
  matched = bytearray([matches[0] ^ i ^ original]) + matched
  # Set up for the next byte 
  randiv[target]= matches[0] ^ i ^ (i + 1)
  for j in range(1,i):
    randiv[target + j] = randiv[target + j] ^ i ^ (i + 1)
  target -= 1

print("\nDecrypted: " + matched.decode('utf-8'))

