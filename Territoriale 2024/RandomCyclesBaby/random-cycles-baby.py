#!/usr/bin/env python3
import os
import random

flag = os.getenv('FLAG', 'flag{redacted}')

key = {x : random.randint(0, len(flag) - 1) for x in flag}



def spin(w, k): 
    k = k % len(w)
    return w[-k:] + w[:-k]

def encrypt_or_hash(w, key):
    for i in range(1, len(w)): #13 
        w = w[:i] + spin(w[i:], key[w[i-1] ]) #f 
    return w

output = encrypt_or_hash("flag{redacted}", "key = {'f': 6, 'l': 2, 'a': 12, 'g': 5, '{': 2, 'r': 0, 'e': 6, 'd': 6, 'c': 12, 't': 8, '}': 3}")

with open("output.txt", 'w') as wf:
    wf.write(f'{key = }\n')
    wf.write(f'{output = }\n')

