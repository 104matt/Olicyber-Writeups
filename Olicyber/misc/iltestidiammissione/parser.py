from pwn import *

# elf = context.binary = ELF('./')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("test1.challs.olicyber.it", 15004)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    ''')
else:
    conn = elf.process()


conn.recvuntil(b"Livello 1:")
conn.recvline()
lineanum = conn.recvline().split()
print(lineanum)

line = conn.recvline().strip().decode()
buttons = []
while(line != ""):
    buttons.append(line.split())
    line = conn.recvline().strip().decode()
print(buttons)
response = []
contnum = 0
for button in buttons:
    
    molt = 5 - int(lineanum[contnum])
    print(molt)
    for i in range(molt):
        response.append(buttons[i])
    contnum+=1
conn.sendline(response)
print(response)

    
conn.interactive()
