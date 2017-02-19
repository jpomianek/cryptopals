#!/usr/local/bin/python3

# Challenge 22: Crack an MT19937 seed

import random
import time
from MT19937 import MT19937

random.seed()

def randomsleepcrack():
  """Waits a random interval, seeds the RNG with the current timestamp, extracts one random integer and returns it"""
  time.sleep(random.randint(40,10001))
  timestamp = int(time.time())
  print("Seeding with timestamp",timestamp)
  m = MT19937(timestamp)
  time.sleep(random.randint(40,10001))
  extracted = m.extract_number()
  print("Random number:", str(extracted))
  return extracted

def bruteforceseed(num):
  """Attempts to brute-force the MT19937 seed value using recent (and future) timestamp values)""" 
  for i in range(1472077165,1482076170):
    m = MT19937(i)
    if (m.extract_number() == num):
      print("Cracked seed value was:", i)
      return i

# Crack 50 seed values for funsies
for i in range(50):
  val = randomsleepcrack()
  bruteforceseed(val)
