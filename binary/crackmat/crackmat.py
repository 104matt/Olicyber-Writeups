from pwn import *
from z3 import *

elf = context.binary = ELF('./crackmat')
context.terminal = ['tmux', 'splitw', '-h']
if args.REMOTE:
    conn = remote("formatted.challs.olicyber.it", 10305)
elif args.GDB:
    conn = gdb.debug([elf.path], gdbscript='''
    b main
    c
    b controllo_flag
    ''')
else:
    conn = elf.process()

a1 = ''
v2 = False
def dionegraccio(a1):
    v2 = a1 * a1 - 204 * a1 == -10404
    if ( a1[1] * a1[1] - 216 * a1[1] != -11664 ):
        v2 = 0
    if ( a1[2] * a1[2] - 194 * a1[2] != -9409 ):
        v2 = 0
    if ( a1[3] * a1[3] - 206 * a1[3] != -10609 ):
        v2 = 0
    if ( a1[4] * a1[4] - 246 * a1[4] != -15129 ):
        v2 = 0
    if ( a1[5] * a1[5] - 200 * a1[5] != -10000 ):
        v2 = 0
    if ( a1[6] * a1[6] - 102 * a1[6] != -2601 ):
        v2 = 0
    if ( a1[7] * a1[7] - 232 * a1[7] != -13456 ):
        v2 = 0
    if ( a1[8] * a1[8] - 202 * a1[8] != -10201 ):
        v2 = 0
    if ( a1[9] * a1[9] - 228 * a1[9] != -12996 ):
        v2 = 0
    if ( a1[10] * a1[10] - 218 * a1[10] != -11881 ):
        v2 = 0
    if ( a1[11] * a1[11] - 210 * a1[11] != -11025 ):
        v2 = 0
    if ( a1[12] * a1[12] - 220 * a1[12] != -12100 ):
        v2 = 0
    if ( a1[13] * a1[13] - 194 * a1[13] != -9409 ):
        v2 = 0
    if ( a1[14] * a1[14] - 220 * a1[14] != -12100 ):
        v2 = 0
    if ( a1[15] * a1[15] - 232 * a1[15] != -13456 ):
        v2 = 0
    if ( a1[16] * a1[16] - 202 * a1[16] != -10201 ):
        v2 = 0
    if ( a1[17] * a1[17] - 190 * a1[17] != -9025 ):
        v2 = 0
    if ( a1[18] * a1[18] - 96 * a1[18] != -2304 ):
        v2 = 0
    if ( a1[19] * a1[19] - 250 * a1[19] != -15625 ):
        return 0
    return v2

conn.interactive()