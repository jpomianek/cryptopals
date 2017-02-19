#!/usr/local/bin/python3
# Challenge 7: AES in ECB mode
# Decrypt a file that's been encrypted via AES-128 in ECB using the
# key "YELLOW SUBMARINE"

# Encrypted file can be found at
# http://www.cryptopals.com/static/challenge-data/7.txt

import base64
from Crypto.Cipher import AES
from os.path import isfile

def aes_ecb_dec(data, key):
  obj = AES.new(key, AES.MODE_ECB)
  return obj.decrypt(bytes(data))

if not isfile('7.txt'):
  print('7.txt not found. Quitting.')
  quit()
with open('7.txt') as f:
  lines = [x.strip('\n') for x in f.readlines()]
ciphertext = base64.b64decode(''.join(lines))

key = 'YELLOW SUBMARINE'

plaintext = aes_ecb_dec(ciphertext, key)

print(plaintext)
