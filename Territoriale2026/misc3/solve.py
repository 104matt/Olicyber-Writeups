from pwn import *

conn = remote("10.45.1.2", 26408)
conn.recvuntil(b'>')
conn.sendline(b'select_wallet')
conn.sendline(b'0xBABE')
conn.recvuntil(b'>')
conn.sendline(b'select_coin')
conn.sendline(b'OLI')
conn.recvuntil(b'>')
conn.sendline(b'authenticate')
conn.recvline()
conn.sendline(b'Han')
conn.recvline()
conn.sendline(b'Vader')
conn.recvline()
conn.sendline(b'Kashyyyk')
conn.recvuntil(b'>')
conn.sendline(b'topup_wallet')
conn.recvuntil(b'>')
conn.sendline(b'list_drinks')
conn.sendline(b'buy_drink')
conn.sendline(b'Darksaber Distillate')




conn.interactive()