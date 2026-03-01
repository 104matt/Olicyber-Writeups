from pwn import *

elf = context.binary = ELF('./dynamicsecret')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.interactive()