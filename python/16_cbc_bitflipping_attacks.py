#!/usr/local/bin/python3
# Challenge 16: CBC bitflipping attacks
# Flip bits in a generated ciphertext until we arrive at 'admin'

import random
from Crypto.Cipher import AES

random.seed()
randkey = bytes([random.randint(0,255) for i in range(0,16)])
randiv = bytes([random.randint(0,255) for i in range(0,16)])

arraysplit = lambda a, n : [a[i:i+n] for i in range(0,len(a),n)]
xor_arrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

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

def stringprep(userstr):
  s = 'comment1=cooking%20MCs;userdata=' + userstr + ';comment2=%20like%20a%20pound%20of%20bacon'
  s = s.replace(';','\';\'')
  s = s.replace('=','\'=\'')
  bs = bytes(s,'utf-8')
  print("Original input: " + bs.decode('utf-8'))
  return aes_cbc_enc(pkcs7(bs), randkey, randiv)

def verify(data):
  s = aes_cbc_dec(data, randkey, randiv)
  s = pkcs7_validate(s)
  return bytes(';admin=true;','utf-8') in s


crypted = stringprep('..............:admin-true:')

if verify(crypted):
  print("We have admin")
else:
  print("We don't have admin")

match = {}
print("\nFlipping bits in ciphertext until arriving at the desired string of ';admin=true;'\n")
for i in range(0,256):
  crypted[36]=i
  crypted[42]=i
  crypted[47]=i
  s = aes_cbc_dec(crypted, randkey, randiv)
  if (chr(s[52])==";"):
    match[36] = i 
  if (chr(s[58])=="="):
    match[42] = i 
  if (chr(s[63])==";"):
    match[47] = i 
  if (len(match) == 3):
    break 
crypted[36]=match[36]
crypted[42]=match[42]
crypted[47]=match[47]
s = aes_cbc_dec(crypted, randkey, randiv)
print("'Corrupted' binary, decrypted:", s)
if verify(crypted):
  print("We have admin")
else:
  print("We don't have admin")

