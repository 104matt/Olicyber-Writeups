from pwn import *

elf = context.binary = ELF('./secureGate')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("securegate.challs.olicyber.it", 12005)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.interactive()