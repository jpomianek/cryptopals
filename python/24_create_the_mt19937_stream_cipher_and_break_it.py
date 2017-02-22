#!/usr/local/bin/python3
# Challenge 24: Create the MT19937 stream cipher and break it

from MT19937 import MT19937

import re
import random
import string
import curses
from curses import wrapper

xor_byte_arrays = lambda a,b : bytearray(map(lambda x,y: x^y, a,b))

def mt19937_stream_encipher(seed, mystr):
  m1 = MT19937(seed)
  crypted = bytearray()
  for i in range(0,len(mystr),4):
    # Extract a 32-bit integer and break it into bytes
    myint = m1.extract_number()
    stream = [myint >> 24, (myint & 16711680) >> 16, (myint & 65280) >> 8, \
        myint & 255]
    segment = mystr[i:i+4]
    crypted += xor_byte_arrays(segment,stream[:len(segment)])
  return crypted

def random_encrypt(plaintext):
  #Prepend a random number of random characters
#  randpad = bytes([random.randint(0, 255) for i in range(0,16)]) 
  randpad = ''.join(random.choice(string.printable) for i in
      range(random.randint(0,255)))
  pt = bytearray(randpad + plaintext,'utf-8')
  seed = random.randint(0, 65536)
  print("Whispered aside, to the audience: the seed is...", seed)
  return mt19937_stream_encipher(seed, pt)

#stdscr = curses.initscr()

crypted = random_encrypt('A'*14)
print("Attempting to crack the seed value...")
freq = [0] * 65536
most = -1
for i in range(65535):
  s = mt19937_stream_encipher(i, crypted)
  try:
      s_decoded = s.decode('utf-8')
  except UnicodeDecodeError:
      next 
  else: 
      freq[i] = len(re.findall("[ETAOIN SHRDLU]", s_decoded, re.IGNORECASE))
      if freq[i] > most:
        print(i,freq[i], mt19937_stream_encipher(i,crypted))
        top = i
        most = freq[i]

print("Best guess:",top)
print("Decrypt:",mt19937_stream_encipher(top, crypted))
