from pwn import *
import base64
import math
import codecs
import json
conn = remote('based.challs.olicyber.it', 10600)

def toBinary(a):
    binary_strings = [bin(ord(i))[2:].zfill(8) for i in a]
    return ''.join(binary_strings)[1:]


def bin_to_str(b):
    hex_string = hex(int(b, 2))[2:]
    if len(hex_string) % 2 != 0:
        hex_string = '0' + hex_string
    s = codecs.decode(hex_string, 'hex').decode()
    return s
conn.recvline()
conn.recvline()
conn.recvline()
conn.recvline()
calc = conn.recvline()
print(calc.decode())
if b' a base64'in calc:
    print("To Base64")
    conn.recvuntil(b': "')
    num = conn.recvuntil(b'"')[:-1]
    print(num.decode())
    res = {'answer' : base64.b64encode(num).decode('utf-8')}
    print(res)
elif b' a binario' in calc:
    print("To Binario")
    conn.recvuntil(b': "')
    num = conn.recvuntil(b'"')[:-1]
    print(num.decode())
    res = {'answer' : f"{toBinary(num.decode())}"}
    print(res)
elif b' a esadecimale' in calc:
    print("To Hex")
    conn.recvuntil(b': "')
    num = conn.recvuntil(b'"')[:-1]
    print(num.decode())
    res = {'answer' : f"{num.hex()}"}
    print(res)
elif b' da base64' in calc:
    print("From Base64")
    conn.recvuntil(b': "')
    num = conn.recvuntil(b'"')[:-1]
    print(num.decode())
    res = {'answer' : base64.b64decode(num).decode('utf-8')}
    print(res)
elif b' da binario' in calc:
    print("From Binario")
    conn.recvuntil(b': "')
    num = conn.recvuntil(b'"')[:-1]
    print(num.decode())
    res = {'answer' : f"{bin_to_str(num)}"}
    print(res)
elif b' da esadecimale' in calc:
    print("From Hex")
    conn.recvuntil(b': "')
    num = conn.recvuntil(b'"')[:-1]
    print(num.decode())
    res = {'answer' : bytes.fromhex(num.decode()).decode('utf-8')}
    print(res)

conn.sendline(json.dumps(res))
while True:
    try:
        conn.recvuntil(b"sto")
    except:
        conn.interactive()
    calc = conn.recvline()
    print(calc.decode())
    if b' a base64'in calc:
        print("To Base64")
        conn.recvuntil(b': "')
        num = conn.recvuntil(b'"')[:-1]
        print(num.decode())
        res = {'answer' : base64.b64encode(num).decode('utf-8')}
        print(res)
    elif b' a binario' in calc:
        print("To Binario")
        conn.recvuntil(b': "')
        num = conn.recvuntil(b'"')[:-1]
        print(num.decode())
        res = {'answer' : f"{toBinary(num.decode())}"}
        print(res)
    elif b' a esadecimale' in calc:
        print("To Hex")
        conn.recvuntil(b': "')
        num = conn.recvuntil(b'"')[:-1]
        print(num.decode())
        res = {'answer' : f"{num.hex()}"}
        print(res)
    elif b' da base64' in calc:
        print("From Base64")
        conn.recvuntil(b': "')
        num = conn.recvuntil(b'"')[:-1]
        print(num.decode())
        res = {'answer' : base64.b64decode(num).decode('utf-8')}
        print(res)
    elif b' da binario' in calc:
        print("From Binario")
        conn.recvuntil(b': "')
        num = conn.recvuntil(b'"')[:-1]
        print(num.decode())
        res = {'answer' : f"{bin_to_str(num)}"}
        print(res)
    elif b' da esadecimale' in calc:
        print("From Hex")
        conn.recvuntil(b': "')
        num = conn.recvuntil(b'"')[:-1]
        print(num.decode())
        res = {'answer' : bytes.fromhex(num.decode()).decode('utf-8')}
        print(res)

    conn.sendline(json.dumps(res))
conn.interactive()