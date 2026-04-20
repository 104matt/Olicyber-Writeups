#!/usr/bin/env python3

flag = 'flag{redacted_redacted_redacted_ABC}'

def encrypt(flag):
    rows = [flag[i:i+6] for i in range(0, len(flag),6)]
    res = ""
    for i in range(len(rows)):
        for j in range(len(rows)):
            res += rows[j][(i+j) % len(rows[0])]
    return res

print(encrypt(flag))
