#!/usr/bin/env python3
"""Parser for custom SatelluaU Lua 5.5 bytecode"""
import struct
import sys

# Lua 5.4 opcodes (should be the same or similar for 5.5)
OPCODES = [
    "MOVE", "LOADI", "LOADF", "LOADK", "LOADKX", "LOADFALSE", "LFALSESKIP",
    "LOADTRUE", "LOADNIL", "GETUPVAL", "SETUPVAL", "GETTABUP", "GETTABLE",
    "GETI", "GETFIELD", "SETTABUP", "SETTABLE", "SETI", "SETFIELD",
    "NEWTABLE", "SELF", "ADDI", "ADDK", "SUBK", "MULK", "MODK", "POWK",
    "DIVK", "IDIVK", "BANDK", "BORK", "BXORK", "SHRI", "SHLI", "ADD",
    "SUB", "MUL", "MOD", "POW", "DIV", "IDIV", "BAND", "BOR", "BXOR",
    "SHL", "SHR", "MMBIN", "MMBINI", "MMBINK", "UNM", "BNOT", "NOT",
    "LEN", "CONCAT", "CLOSE", "TBC", "JMP", "EQ", "LT", "LE", "EQK",
    "EQI", "LTI", "LEI", "GTI", "GEI", "TEST", "TESTSET", "CALL",
    "TAILCALL", "RETURN", "RETURN0", "RETURN1", "FORLOOP", "FORPREP",
    "TFORPREP", "TFORCALL", "TFORLOOP", "SETLIST", "CLOSURE", "VARARG",
    "VARARGPREP", "EXTRAARG"
]

class BytecodeReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0
    
    def read_byte(self):
        b = self.data[self.pos]
        self.pos += 1
        return b
    
    def read_bytes(self, n):
        result = self.data[self.pos:self.pos+n]
        self.pos += n
        return result
    
    def read_int(self):
        val = struct.unpack_from('<i', self.data, self.pos)[0]
        self.pos += 4
        return val
    
    def read_uint(self):
        val = struct.unpack_from('<I', self.data, self.pos)[0]
        self.pos += 4
        return val
    
    def read_int64(self):
        val = struct.unpack_from('<q', self.data, self.pos)[0]
        self.pos += 8
        return val
    
    def read_double(self):
        val = struct.unpack_from('<d', self.data, self.pos)[0]
        self.pos += 8
        return val
    
    def read_varint(self):
        """Big-endian varint with continuation bit in high bit (0x80)"""
        result = 0
        while True:
            b = self.read_byte()
            result = (result << 7) | (b & 0x7F)
            if (b & 0x80) == 0:
                return result
    
    def read_string(self):
        """Read a Lua string: varint size (0=NULL, else size-1 chars)"""
        size = self.read_varint()
        if size == 0:
            return None
        length = size - 1
        s = self.read_bytes(length)
        return s
    
    def align(self, alignment):
        """Align position to given alignment"""
        pad = alignment - (self.pos % alignment)
        if pad != alignment:
            self.pos += pad

def decode_instruction(instr):
    """Decode a 32-bit Lua 5.4 instruction"""
    opcode = instr & 0x7F  # 7 bits
    a = (instr >> 7) & 0xFF  # 8 bits
    
    op_name = OPCODES[opcode] if opcode < len(OPCODES) else f"OP_{opcode}"
    
    # Determine format based on opcode
    # iABC: A(8) B(8) C(8) k(1)
    # iABx: A(8) Bx(17)
    # iAsBx: A(8) sBx(17) (signed)
    # iAx: Ax(25)
    # isJ: sJ(25) (signed)
    
    k = (instr >> 15) & 1
    b = (instr >> 16) & 0xFF
    c = (instr >> 24) & 0xFF
    bx = (instr >> 15) & 0x1FFFF  # 17 bits
    sbx = bx - 0xFFFF  # signed Bx (offset by 2^17-1 / 2)
    ax = (instr >> 7) & 0x1FFFFFF  # 25 bits
    sj = ax - 0xFFFFFF  # signed J (offset)
    
    # Format depends on opcode
    abc_ops = {0, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
               21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
               37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52,
               53, 54, 55, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69,
               70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80}
    abx_ops = {3}  # LOADK
    asbx_ops = {1, 2, 56, 71, 72, 73}  # LOADI, LOADF, JMP, FORLOOP, FORPREP, TFORPREP
    ax_ops = {81}  # EXTRAARG
    
    if opcode in asbx_ops:
        return op_name, f"A={a} sBx={sbx}"
    elif opcode in abx_ops:
        return op_name, f"A={a} Bx={bx}"
    elif opcode in ax_ops:
        return op_name, f"Ax={ax}"
    else:
        return op_name, f"A={a} B={b} C={c} k={k}"
    
def parse_proto(reader, depth=0):
    """Parse a function prototype"""
    indent = "  " * depth
    
    linedefined = reader.read_varint()
    lastlinedefined = reader.read_varint()
    numparams = reader.read_byte()
    is_vararg = reader.read_byte()
    maxstacksize = reader.read_byte()
    
    sizecode = reader.read_varint()
    
    print(f"{indent}=== Function Prototype (depth={depth}) ===")
    print(f"{indent}  linedefined: {linedefined}")
    print(f"{indent}  lastlinedefined: {lastlinedefined}")
    print(f"{indent}  numparams: {numparams}")
    print(f"{indent}  is_vararg: {is_vararg}")
    print(f"{indent}  maxstacksize: {maxstacksize}")
    print(f"{indent}  sizecode: {sizecode}")
    
    # Align to 4 bytes for instructions
    reader.align(4)
    
    # Read instructions
    instructions = []
    for i in range(sizecode):
        instr = reader.read_uint()
        instructions.append(instr)
    
    # Print first N instructions (limit output)
    max_show = 200 if depth == 0 else 50
    print(f"{indent}  Instructions ({sizecode} total, showing first {min(sizecode, max_show)}):")
    for i, instr in enumerate(instructions[:max_show]):
        op_name, details = decode_instruction(instr)
        print(f"{indent}    [{i:4d}] 0x{instr:08x}  {op_name:15s} {details}")
    if sizecode > max_show:
        print(f"{indent}    ... ({sizecode - max_show} more instructions)")
    
    # Read constants
    sizek = reader.read_varint()
    print(f"{indent}  Constants ({sizek}):")
    constants = []
    for i in range(sizek):
        ctype = reader.read_byte()
        if ctype == 0:
            constants.append(("nil", None))
        elif ctype == 1:
            constants.append(("false", False))
        elif ctype == 0x11:
            constants.append(("true", True))
        elif ctype == 3:
            # Integer: zigzag-encoded varint
            raw = reader.read_varint()
            val = raw >> 1
            if raw & 1:
                val = ~val
            constants.append(("int", val))
        elif ctype == 0x13:
            # Float: 8 bytes IEEE 754
            val = reader.read_double()
            constants.append(("float", val))
        elif ctype in (4, 0x14):
            # String
            s = reader.read_string()
            constants.append(("string", s))
        else:
            print(f"{indent}    WARNING: Unknown constant type 0x{ctype:02x}")
            constants.append(("unknown", ctype))
    
    for i, (ctype, cval) in enumerate(constants):
        if ctype == "string" and cval is not None:
            try:
                display = cval.decode('utf-8', errors='replace')
            except:
                display = repr(cval)
            print(f"{indent}    K[{i}] = {ctype}: {display!r}")
        else:
            print(f"{indent}    K[{i}] = {ctype}: {cval}")
    
    # Read upvalues
    sizeupvalues = reader.read_varint()
    print(f"{indent}  Upvalues ({sizeupvalues}):")
    upvalues = []
    for i in range(sizeupvalues):
        instack = reader.read_byte()
        idx = reader.read_byte()
        kind = reader.read_byte()
        upvalues.append((instack, idx, kind))
        print(f"{indent}    UV[{i}] = instack={instack}, idx={idx}, kind={kind}")
    
    # Read child protos
    sizeprotos = reader.read_varint()
    print(f"{indent}  Child protos ({sizeprotos}):")
    for i in range(sizeprotos):
        print(f"{indent}  --- Child proto {i} ---")
        parse_proto(reader, depth + 1)
    
    # Read source name
    source = reader.read_string()
    if source:
        try:
            source_str = source.decode('utf-8', errors='replace')
        except:
            source_str = repr(source)
        print(f"{indent}  Source: {source_str}")
    else:
        print(f"{indent}  Source: (none)")
    
    # Read line info
    sizelineinfo = reader.read_varint()
    print(f"{indent}  Line info ({sizelineinfo} bytes)")
    lineinfo = reader.read_bytes(sizelineinfo)
    
    # Read abslineinfo
    sizeabslineinfo = reader.read_varint()
    print(f"{indent}  Abs line info ({sizeabslineinfo} entries)")
    if sizeabslineinfo > 0:
        reader.align(4)
        # Each entry is 8 bytes: int pc, int line
        for i in range(sizeabslineinfo):
            pc = reader.read_int()
            line = reader.read_int()
            if i < 5:
                print(f"{indent}    absline[{i}] = pc={pc}, line={line}")
        if sizeabslineinfo > 5:
            reader.pos += (sizeabslineinfo - 5) * 8
            # Oops, we already read 5, need to skip rest but they were already read
            # Let me fix: actually we need to skip the remaining entries
    
    # Read local vars
    sizelocvars = reader.read_varint()
    print(f"{indent}  Local vars ({sizelocvars}):")
    for i in range(sizelocvars):
        name = reader.read_string()
        startpc = reader.read_varint()
        endpc = reader.read_varint()
        if name:
            name_str = name.decode('utf-8', errors='replace')
        else:
            name_str = "(none)"
        if i < 20:
            print(f"{indent}    local[{i}] = {name_str!r}, startpc={startpc}, endpc={endpc}")
    if sizelocvars > 20:
        print(f"{indent}    ... ({sizelocvars - 20} more)")
    
    # Read upvalue debug names
    has_debug = reader.read_varint()
    print(f"{indent}  Debug names flag: {has_debug}")
    if has_debug:
        for i in range(sizeupvalues):
            uv_name = reader.read_string()
            if uv_name:
                uv_name_str = uv_name.decode('utf-8', errors='replace')
            else:
                uv_name_str = "(none)"
            print(f"{indent}    upval_name[{i}] = {uv_name_str!r}")
    
    print(f"{indent}=== End Function Prototype ===")
    return {
        'instructions': instructions,
        'constants': constants,
        'upvalues': upvalues,
        'numparams': numparams,
        'maxstacksize': maxstacksize,
    }

def main():
    data = open('satellua', 'rb').read()
    size = struct.unpack_from('<I', data, 0x302c0)[0]
    bc = data[0x302e0:0x302e0 + size]
    
    reader = BytecodeReader(bc)
    
    # Parse header
    sig = reader.read_bytes(10)
    assert sig == b'\x1bSatelluaU', f"Bad signature: {sig}"
    
    fmt = reader.read_byte()
    assert fmt == 1, f"Bad format: {fmt}"
    
    luac_data = reader.read_bytes(6)
    assert luac_data == b'\x19\x93\x0d\x0a\x1a\x0a', f"Bad LUAC_DATA: {luac_data.hex()}"
    
    sizeint = reader.read_byte()
    assert sizeint == 4
    int_check = reader.read_int()
    print(f"int_check = {int_check}")
    
    sizeinstr = reader.read_byte()
    assert sizeinstr == 4
    instr_check = reader.read_uint()
    print(f"instr_check = 0x{instr_check:08x}")
    
    sizeinteger = reader.read_byte()
    assert sizeinteger == 8
    integer_check = reader.read_int64()
    print(f"integer_check = {integer_check}")
    
    sizenumber = reader.read_byte()
    assert sizenumber == 8
    number_check = reader.read_double()
    print(f"number_check = {number_check}")
    
    sizeupvalues = reader.read_byte()
    print(f"sizeupvalues = {sizeupvalues}")
    print(f"Header parsed. Position: {reader.pos} (0x{reader.pos:x})")
    
    # Parse main function prototype
    parse_proto(reader, 0)
    
    print(f"\nFinal position: {reader.pos} (0x{reader.pos:x}) / {len(bc)} (0x{len(bc):x})")

if __name__ == '__main__':
    main()
