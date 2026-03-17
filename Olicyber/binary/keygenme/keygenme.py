from pwn import *

elf = context.binary = ELF('./keygenme')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("keygenme.challs.olicyber.it", 10017)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.interactive()