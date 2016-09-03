#!/usr/local/bin/python3
# Challenge 13: ECB cut-and-paste

import random
from Crypto.Cipher import AES

random.seed()
randkey = bytes([random.randint(0,255) for i in range(0,16)])

def pkcs7(data):
  """Pad a given string according to PKCS#7"""
  l = 16 - (len(data) % 16)
  data += bytes([l])*l
  return data

def aes_ecb_enc(data, key):
  """Encrypt data with the provided key using AES in CBC mode. Return
  the encrypted string
  """
  obj = AES.new(key, AES.MODE_ECB)
  return obj.encrypt(bytes(data))

def aes_ecb_dec(data, key):
  """Decrypt data with the provided key using AES in CBC mode. Return
  the decryped string
  """
  obj = AES.new(key, AES.MODE_ECB)
  return obj.decrypt(bytes(data))

def kvparser(input):
  """Take "key1=val1&key2=val2" and parse out/print key-value pairs.
  
     Does not return data.
  """
  myvars = {}
  arr = input.split('&')
  for kvpair in arr:
    kv = kvpair.split('=')
    if(len(kv) == 2):
      myvars[kv[0]] = kv[1]
  for var in myvars:
    print(var + ' set to ' + myvars[var])

def profile_for(email):
  """Generate k-v pair for provided email address and append kv pairs
     for uid and role.
  """
  email = email.replace('&','\'&\'')
  email = email.replace('=','\'=\'')
  return 'email=' + email + '&uid=10&role=user'

# Generate a base ciphertext using a dummy email that aligns our
# target characters properly
profile = bytes(profile_for('aaaaaa@me.admin'),'utf-8')
print("Plaintext of our non-privileged auth string:")
print(pkcs7(profile),"\n")

print("Capturing 'admin&', which is in the second encrypted block.")
# [16:32] == b'admin&uid=10&rol'
print(profile[16:32],"\n")
lastblock = aes_ecb_enc(pkcs7(profile),randkey)[16:32]

print("Swapping in our badguy email address while aligning\n" + 
      "'role=' to the end of a block and capturing it.")
# [0:32] == b'email=badguy@abc.pl&uid=10&role='
profile = bytes(profile_for('badguy@abc.pl'),'utf-8')
print(profile[0:32])
firstblock = aes_ecb_enc(pkcs7(profile),randkey)[0:32]

combined = firstblock + lastblock

kv = aes_ecb_dec(combined,randkey)
print("\nAfter combinging, verifying our copy-pasting worked...")
kvparser(kv.decode('utf-8'))
