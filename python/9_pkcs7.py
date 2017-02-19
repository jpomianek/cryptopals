#!/usr/local/bin/python3
# Challenge 9: Implement PKCS#7 padding

import pprint

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

string = 'YELLOW SUBMARINE'
print("'" + string + "' with PKCS#7 padding, to 20 bytes: ")
pprint.pprint(pkcs7(string,20))
