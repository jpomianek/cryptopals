#!/usr/local/bin/python3
# Challenge 11: An ECB/CBC detection oracle
# "Write a function that encrypts data under an unknown key --- that
# is, a function that generates a random key and encrypts under it. "

import base64
import pprint
import random
import collections

from Crypto.Cipher import AES

xor_single_byte_on_array = lambda a, b : [i ^ b for i in a]
hex2bytes = lambda s : [int(s[i:i+2],16) for i in range(0,len(s),2)]
byte_array2string = lambda a : ''.join([chr(i) for i in a])
xor_arrays = lambda a, b: bytes(map(lambda x, y: x ^ y, a, b))

# Split array a into b sized blocks
arraysplit = lambda a, b : [a[i:i+b] for i in range(0,len(a),b)]

def pkcs7(data):
  l = 16 - (len(data) % 16)
  data += bytes([l])*l
  return data

def encryption_oracle(s):
  """Randomly encrypt using ECB or CBC mode

  Arguments:
    s (string) : plaintext string

  Returns:
    array: [cyphertext string, AES mode used (as string)]
  """
  randkey = b''
  randkey += bytearray([random.randint(0,255) for i in range(0,16)])
  randiv = bytes([random.randint(0,255) for i in range(0,16)])
  pre = bytes([random.randint(0,255) for i in range(0,random.randint(5,10))])
  post = bytes([random.randint(0,255) for i in range(0,random.randint(5,10))])
  string = pre + bytes(s,'utf-8') + post
  if(random.randint(0,1)):
    return [aes_cbc_enc(pkcs7(string), randkey, randiv), 'CBC']
  else:
    obj = AES.new(randkey, AES.MODE_ECB)
    return [aes_ecb_enc(pkcs7(string), randkey),'ECB']

def aes_ecb_enc(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

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
  """ Detect AES's ECB or CBC mode

  Arguments: 
    ba (array of bytes): cipher text

  Returns:
    string: "ECB" or "CBC"
  """
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

for i in range(0,100):
  string = 'a'*48
  enc = encryption_oracle(string)
  detected = ecb_cbc_detect(enc[0])
  if (detected == enc[1]):
    print("Detected: " + detected)
  else:
    print("Failed to detect " + enc[1]) 

