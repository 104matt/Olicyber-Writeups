from pwn import *

elf = context.binary = ELF('./intagram_generator')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("intagram.challs.olicyber.it", 10101)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.interactive()
