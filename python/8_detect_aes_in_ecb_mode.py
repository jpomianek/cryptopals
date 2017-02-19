#!/usr/local/bin/python3
# Challenge 8: Detect AES in ECB mode

# Among a set of hex-encoded plaintexts find the one that has been
# encrypted using ECB mode. 

# Target file can be found at
# http://www.cryptopals.com/static/challenge-data/8.txt

import collections

hex2bytes = lambda s :[int(s[i:i+2],16) for i in range(0,len(s),2)]
aesblocks = lambda a : [a[i:i+16] for i in range(0,len(a),16)]
byte_array2string = lambda a : ''.join([chr(i) for i in a])

with open('8.txt') as f:
  lines = [x.strip('\n') for x in f.readlines()]

uniqblocks = {}
# ECB mode will generate the same ciphertext block for a given plaintext
# block; a telltale sign is then ciphertext block recurrence. 
for l in lines:
  byte_array = hex2bytes(l)
  blocks = aesblocks(byte_array)
  uniqblocks[l] = collections.defaultdict(int)
  for b in blocks:
    uniqblocks[l][byte_array2string(b)] += 1

for l in uniqblocks:
  repeats = list(filter(lambda x: uniqblocks[l][x] > 1, uniqblocks[l])) 
  for r in repeats:
    print(l + " contains repeated blocks:\n" + str(repeats) + "(" +
        str(uniqblocks[l][r]) + ")\n")
