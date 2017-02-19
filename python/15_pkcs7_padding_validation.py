#!/usr/local/bin/python3
# Challenge 15: PKCS#7 padding validation

def pkcs7_validate(data):
  'Verify a given string is properly padded using PKCS#7'

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

