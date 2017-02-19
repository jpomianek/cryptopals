#!/usr/local/bin/python3
# Challenge 10: Implement CBC mode

# Using AES's ECB mode, implement functions to en/decrypt in CBC
# mode

# Encryped file 10.txt is available at
# http://www.cryptopals.com/static/challenge-data/10.txt
import base64
import pprint
import random

from os.path import isfile
from Crypto.Cipher import AES

random.seed()

byte_array2string = lambda a : ''.join([chr(i) for i in a])
xor_arrays = lambda a, b: list(map(lambda x,y:x^y, a, b)) 

# Split array a into b sized blocks
arraysplit = lambda a, b : [a[i:i+b] for i in range(0,len(a),b)]

def pkcs7(string, blocklen):
  """Pad a string according to PKCS#7

  Arguments:
    string (string): Plaintext to be padded
    blocklen (int):  Block length

  Returns:
    String with appropriate padding bytes added.
  """
  padlen = blocklen * (divmod(len(string),blocklen)[0]+1) - len(string)
  string += chr(padlen) * padlen
  return string

def aes_cbc_dec(crypted, key, iv):
  """Decrypt ciphertext using CBC mode

  Arguments: 
    crypted (array of bytes): ciphertext
    key (array of bytes)    : encryption key
    iv (string)             : initialization vector

  Returns:
    Cleartext string
  """

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

def aes_cbc_enc(plaintext, key, iv):
  """Encrypt ciphertext using CBC mode

  Arguments: 
    plaintext (string)      : plaintext
    key (array of bytes)    : encryption key
    iv (string)             : initialization vector

  Returns:
    Encrypted string 
  """
  string2byte_array = lambda s: [ ord(i) for i in s ]
  obj = AES.new(key, AES.MODE_ECB)
  plaintext = pkcs7(plaintext,16)
  prev = string2byte_array(iv)
  crypted = bytearray() 
  for b in arraysplit(plaintext,16):
    xord = xor_arrays(prev,string2byte_array(b))
    result = obj.encrypt(byte_array2string(xord))
    crypted += result 
    prev = string2byte_array(result)
  return byte_array2string(crypted)

if not isfile('10.txt'):
  print('10.txt not found. Quitting.')
  quit()
with open('10.txt') as f:
  lines = [x.strip('\n') for x in f.readlines()]

crypted = base64.b64decode(''.join(lines))
key = 'YELLOW SUBMARINE'

plaintext = aes_cbc_dec(crypted, key, chr(0)*16)
print(plaintext)
