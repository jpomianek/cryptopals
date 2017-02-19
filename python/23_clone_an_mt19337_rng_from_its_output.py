#!/usr/local/bin/python3
# Exercise 21: Clone an MT19937 RNG from its output

import random
from MT19937 import MT19937

def untemper(y):
  # inverse of: y = y ^ (y >> 18)
  y = y ^ (y >> 18)

  # inverse of: y = y ^ ((y << 15) & 4022730752)
  # Use previous 15 (original) bits to restore next set of 15, keeping in mind
  # the original bitmask.
  bitmask = 4022730752 & 1073709056
  y = y ^ ((y << 15) & bitmask)
  bitmask = 4022730752 & 3221225472
  y = y ^ ((y << 15) & bitmask)

  # inverse of: y = y ^ ((y << 7) & 2636928640)
  # Use previous 7 bits to restore next set of 7, keeping in mind the
  # original bitmask.
  # 8128 =                          '1111111000000'
  bitmask = 2636928640 & 8128
  y = y ^ ((y << 7) & bitmask)
  # 1040384 =                '11111110000000000000'
  bitmask = 2636928640 & 1040384
  y = y ^ ((y << 7) & bitmask)
  # 133169152 =       '111111100000000000000000000'
  bitmask = 2636928640 & 133169152
  y = y ^ ((y << 7) & bitmask)
  # 4160749568 = '11111000000000000000000000000000'
  bitmask = 2636928640 & 4160749568
  y = y ^ ((y << 7) & bitmask)

  # inverse of: y = y ^ (y >> 11)
  y = y ^ ((y >> 11) & 2096128)
  y = y ^ ((y & 2095104) >> 11)
  return y

print("Initializing our RNG to-be-cloned with a random seed value...\n")
original=MT19937(random.randint(0,500000))

# The seed value shouldn't matter since we'll be 
# overriding the class's state array and index
print("Initializing our RNG to-be-cloned-into...\n")
clone=MT19937(0)

savestate = []
print("Extracting 624 random numbers from our original RNG, \
inverting them and placing them into a temporary array...\n")
for i in range(0,624):
  n = original.extract_number()
  savestate.append(untemper(n))

print("Transplanting our cloned state array into our clone RNG \
and resetting its index to 0...\n")
clone.brain_transplant(savestate,0)
# Now get caught up to original's current state
print("Extracting 624 random numbers from our cloned MT19937\
 instance and discarding them.")
for i in range(0,624):
  clone.extract_number()

# Let's see if the next extracted "random" numbers are now equal
print("\nNow extracting the next random number from our original and cloned\
 RNGs.")
print("Original, next random number:",str(original.extract_number()))
print("Clone, next random number   :",str(clone.extract_number()))
