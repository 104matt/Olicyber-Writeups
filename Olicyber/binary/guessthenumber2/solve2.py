from pwn import *

elf = context.binary = ELF('./GuessTheNumber2')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("gtn2.challs.olicyber.it", 10023)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    ''')
else:
    conn = elf.process()


conn.send(cyclic(0x80))

conn.interactive()