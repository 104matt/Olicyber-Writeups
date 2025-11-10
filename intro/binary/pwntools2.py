from pwn import *

req = remote("software-18.challs.olicyber.it", 13001)

req.recvuntil(b"...")
req.sendline(b"b")

for i in range(100):
    l = req.recvline().split()
    num = l[-4]
    calc = l[-1]
    pacco = l [-3]
    if b"32-bit" in calc and b"packed" in pacco:
        res = p32(int(num, 16), endianness="little")
    elif b"64-bit" in calc and b"packed" in pacco:
        res = p64(int(num, 16), endianness="little")
    elif b"64-bit" in calc and b"unpacked" in pacco:
        res = u64(num.encode(), endianness="little")
    elif b"32-bit" in calc and b"unpacked" in pacco:
        res = u32(num.encode(), endianness="little")
    req.recvuntil(b":") or req.interactive()
    req.send(res)
    if i == 99:
        req.interactive()
    print(i)


