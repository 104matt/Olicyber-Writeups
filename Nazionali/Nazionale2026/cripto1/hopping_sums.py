#!/usr/bin/env python3

import os
from random import randrange
from math import gcd

flag = os.getenv('FLAG', 'flag{redacted}').encode()
assert flag.startswith(b'flag{') and flag.endswith(b'}')
flag = flag[5:-1]
l = len(flag)

while 1:
    k = randrange(2, l)
    if gcd(k, l) == 1:
        break

enc = []
for i in [(k*i-1)%l for i in range(l)]:
    enc.append((flag[i] + flag[(i+k)%l])&0xff)


print(bytes(enc).hex())

revvare = bytes.fromhex("65909297d7d9d4dbe1db9b686998cfced5e7da9aa7db9bacd8c498a5e7ece5cdbe926ba6cd96a9a3a1dee1ead6d3a4608fd4dddbe7a864a9dfdadc9c")

for i in [(k*i-1)%l for i in range(l)]:
    enc.append((flag[i] + flag[(i+k)%l])&0xff)

print(revvare&0xff)