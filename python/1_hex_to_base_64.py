#!/usr/local/bin/python3

from collections import deque
import struct

base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def hex_to_64(hexstr):
    """Converts a given hexadecimal string to Base-64"""
    queue = deque([]) 
    binstr = ''
    base64str = ''
    for val in hexstr:
        # convert each hex char to binary and append binary values to "arr"
        queue.extend(list("{0:04b}".format(int(val, 16))))
    while(len(queue) >= 24):
        relevantbits = []
        for num in range(0,6):
            relevantbits.append(queue.popleft())
        print(relevantbits)
        base64str = base64str + base64[int(''.join(relevantbits),2)]
    # Handle any padding
    if (len(queue) > 0):
        (nopad, remainder) = divmod(len(queue),6)
        padding = 24 - len(queue) 
        for num in range(0,nopad):            
            relevantbits = []
            for num in range(0,6):
                relevantbits.append(queue.popleft())
            base64str = base64str + base64[int(''.join(relevantbits),2)]
        relevantbits = []
        if (remainder > 0):
            for num in range(0,6-remainder):
                queue.extend(['0'])
            for num in range(0,6):
                relevantbits.append(queue.popleft())
            base64str = base64str + base64[int(''.join(relevantbits),2)] 
        (div, mod) = divmod(padding,6) 
        base64str = base64str + '=' * div
    return base64str
     
base64str = hex_to_64("1234")
print(base64str)
