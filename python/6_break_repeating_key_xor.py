#!/usr/local/bin/python3
# Challenge 6: Break repeating-key XOR

# Enciphered file can be found at 
# http://www.cryptopals.com/static/challenge-data/6.txt

import re
import base64
import collections
from os.path import isfile

str2byte_array = lambda s : [ord(c) for c in s]
hex2byte_array = lambda s : [int(c, 16) for c in s]

byte_array2string = lambda a : ''.join([chr(i) for i in a])
byte_array2hexstr = lambda a : ''.join(["{:x}".format(i) for i in a])

xor_byte_arrays = lambda a,b : list(map(lambda x,y: x^y, a,b))

xor_single_byte_on_array = lambda a, b : [i ^ b for i in a]

xor_multibyte_on_array = lambda b_a, a : xor_byte_arrays(a, ((divmod(len(a),len(b_a))[0]+1)*b_a)[0:len(a)])

def hamming (b1, b2):
  """Calculate the hamming distance between two byte arrays
  
  Arguments:
    b1 (array of bytes)
    b2 (array of bytes, length equal to b1)

  Returns:
    Integer equaling hamming distance.
    https://en.wikipedia.org/wiki/Hamming_distance
  """

  ba1 = list(b1)
  ba2 = list(b2)
  # Count the ones after xor'ing our two blocks to derive the edit
  # (hamming) distance. 
  e_d = xor_byte_arrays(ba1, ba2)
  return len(list(filter(lambda x : x == '1', list(''.join([("{0:b}".format(i)) for i in e_d])))))

if not isfile('6.txt'):
  print('6.txt not found. Quitting.')
  quit() 
with open('6.txt') as f:
  lines = [x.strip('\n') for x in f.readlines()]
ciphertext = base64.b64decode(''.join(lines))

max_keysize = divmod(len(ciphertext),2)[0]

distances = {}

print("Identifying candidates based on hamming distance between blocks 1 and 2.")

for i in range(1,max_keysize + 1):
  # get the hamming distance
  averaged = hamming(ciphertext[0:i],ciphertext[i:i*2]) / i
  # Key length is actually i + 1
  distances[i + 1] = averaged

blocks = {}

print("Brute-forcing with key length candidates: " + str(sorted(distances, key=distances.__getitem__, reverse=True)[0:8]))
for keylen in sorted(distances, key=distances.__getitem__, reverse=True)[0:8]:
  key = ''
  # pivot: build sets of blocks representing every i*keylen byte
  # example: string length 8, key length 4:
  #  string: [0, 1, 2, 3, 4, 5, 6, 7, 8]
  #  blocks[4] = [[0, 5], [1, 6], [2, 7], [3, 8]]

  blocks[keylen] = collections.defaultdict(list)
  for j in (range(0,len(ciphertext))):
    blocks[keylen][divmod(j,keylen)[1]] += [ciphertext[j]]
  # Attempt to crack each collection of bytes for this keylength
  for i in (blocks[keylen]):
    freq = {}
    for j in range(0,256):
      xor_result = xor_single_byte_on_array(blocks[keylen][i], j)
      # Ignore if unprintable characters exist, excepting newline and
      # carriage return
      verboten = list(filter(lambda x: x > 0 and x != 10 and x !=13 and (x < 31 or x > 126), xor_result))
      if (verboten):
        continue
      s = byte_array2string(xor_result)
      freq[j] = len(re.findall("[ETAOIN SHRDLU]", s, re.IGNORECASE))
    # Pick the byte that generated the most hits on our critical letters
    for n in sorted(freq, key=freq.__getitem__, reverse=True)[0:1]:
      key += chr(n)
    if (len(key) == keylen):
      print('Key found: "' + key + "\" (length:" + str(len(key)) + ")\nDecrypt:")
      decrypt = xor_multibyte_on_array(str2byte_array(key), ciphertext)
      print(byte_array2string(decrypt))
