from pwn import *

elf = context.binary = ELF('./sw-19')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("software-19.challs.olicyber.it", 13002)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

conn.recvuntil(b"...")
conn.sendline(b"a")

for i in range(20):
    print(i)
    t = conn.recvuntil(b"> ")
    print(t)
    search = conn.recvuntil(b":")[:-1].decode() #volendo anche strip ma vedo dopo
    print(search)
    payload = elf.sym[f'{search}']
    print(hex(payload))
    conn.sendline(hex(payload))


conn.interactive()

