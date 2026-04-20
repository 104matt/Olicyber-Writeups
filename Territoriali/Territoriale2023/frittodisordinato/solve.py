from pwn import *

elf = context.binary = ELF('./fritto')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("nfritto-disordinato.challs.olicyber.it", 33001)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    ''')
else:
    conn = elf.process()


main_offsettato = hex(elf.sym["main"])


conn.interactive()

corretto = [13, 3, 14, 1, 9, 7, 10, 15, 17, 12, 16, 6, 11, 2, 8, 0, 4, 5]
for i in range(18):
    conn.recvuntil(b'>')
    conn.sendline(b'0')
    conn.recvuntil(b'ro?')
    conn.sendline(f'{i}'.encode())
    conn.recvuntil(b'ci?')
    print()
    conn.sendline(str(corretto[i]).encode())

conn.interactive()