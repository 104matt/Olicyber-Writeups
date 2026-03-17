#!/usr/bin/env python3
import os
import random

flag = os.getenv('FLAG', 'flag{redacted}')

key = {'f': 18, 'l': 58, 'a': 22, 'g': 30, '{': 33, '4': 63, 'p': 68, 'r': 47, 'e': 6, 'n': 56, 't': 5, 'y': 40, '_': 17, '1': 30, 's': 53, 'c': 54, 'o': 63, '0': 67, 'w': 3, '3': 20, 'i': 26, 'u': 37, '6': 16, '5': 26, '9': 63, '8': 50, '}': 26}

def spin(w, k):
    k = k % len(w)
    return w[-k:] + w[:-k]

def encrypt_or_hash(w, key):
    for i in range(1, len(w)):
        w = w[:i] + spin(w[i:], key[w[i-1]])
    return w

output = encrypt_or_hash(flag, key)

with open("output.txt", 'w') as wf:
    wf.write(f'{key = }\n')
    wf.write(f'{output = }\n')
    wf.write(flag)