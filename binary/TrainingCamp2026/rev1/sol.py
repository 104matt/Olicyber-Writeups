from pwn import *


target = bytes([
    0x75, 0x22, 0xC3, 0x24, 0x1F, 0x1E, 0xDE, 0x61,
    0x4B, 0xBB, 0xCB, 0x6E, 0x41, 0x30, 0x5D, 0x99,
    0x85, 0xB3, 0xB3, 0x6E, 0x43, 0xA2, 0x58, 0x92,
    0x9D, 0x1B, 0x93, 0x5A, 0xA7, 0x9A, 0xAD, 0xC8,
    0x85, 0x5B, 0xB7, 0x51,
])


def ror8(b: int, r: int) -> int:
    r &= 7
    if r == 0:
        return b & 0xFF
    return ((b >> r) | ((b << (8 - r)) & 0xFF)) & 0xFF


def recover_flag() -> bytes:
    n = len(target)

    # Undo final reverse_bytes
    state = [target[n - 1 - i] for i in range(n)]

    # Undo addition of index: b[i] += i
    state = [((state[i] - i) & 0xFF) for i in range(n)]

    # Undo rol8 and XOR 0x37
    for i in range(n):
        k = i & 7
        y = state[i]
        x = ror8(y, k)
        state[i] = x ^ 0x37

    return bytes(state)


if __name__ == "__main__":
    flag = recover_flag()
    print(flag.decode(errors="ignore"))

    # Verifica locale opzionale
    elf = context.binary = ELF("./revme")
    if args.GDB:
        io = gdb.debug([elf.path], gdbscript="""
        b main
        continue
        """)
    else:
        io = elf.process()

    io.sendlineafter(b"Give me the flag: ", flag)
    print(io.recvall(timeout=1).decode(errors="ignore"))