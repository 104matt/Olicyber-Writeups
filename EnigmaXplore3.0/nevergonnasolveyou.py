#!/usr/bin/env python3
import sys, os, re, base64, binascii, itertools

FALLBACK_FILE = "lyrics.txt"

ZW_ALL = {
    "\u200b", # ZWSP
    "\u200c", # ZWNJ
    "\u200d", # ZWJ
    "\u2060", # WJ
    "\u2062", # INVISIBLE_TIMES
    "\u2063", # INVISIBLE_SEPARATOR
    "\u2064", # INVISIBLE_PLUS
}
DATA2 = ["\u200b", "\u200c"]                 # 2 simboli (bit)
DATA4 = ["\u200b", "\u200c", "\u200d", "\u2060"]  # 4 simboli (2 bit)
SEPARATORS = {"\u2062", "\u2063", "\u2064"}  # spesso delimitatori

def load_input():
    if not sys.stdin.isatty():
        s = sys.stdin.read()
        if s:
            return s
    if os.path.exists(FALLBACK_FILE):
        return open(FALLBACK_FILE, "rb").read().decode("utf-8", "ignore")
    print("Metti i lyrics in lyrics.txt o pipe su stdin.", file=sys.stderr)
    sys.exit(1)

def only_zw(s):
    return "".join(ch for ch in s if ch in ZW_ALL)

def split_by_separators(zw):
    parts, cur = [], []
    for ch in zw:
        if ch in SEPARATORS:
            if cur:
                parts.append("".join(cur))
                cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts

def bits_to_bytes(bitstr):
    # restituisce le 8 rotazioni possibili (offset 0..7)
    outs = []
    for off in range(8):
        b = bitstr[off:]
        b = b[:len(b)//8*8]
        if not b:
            outs.append((off, b""))
            continue
        outs.append((off, bytes(int(b[i:i+8], 2) for i in range(0, len(b), 8))))
    return outs

def score_text(t):
    if not t:
        return -1
    good = sum(1 for c in t if 32 <= ord(c) <= 126 or c in "\n\r\t {}_:-.,;[]()")
    return good/len(t)

B64 = re.compile(rb"^[A-Za-z0-9+/=\s]+$")
B32 = re.compile(rb"^[A-Z2-7=\s]+$")
HEX = re.compile(rb"^[0-9A-Fa-f\s]+$")

def try_decoders(raw):
    outs = []
    # utf-8
    try:
        txt = raw.decode("utf-8")
        outs.append(("utf8", txt))
    except:
        pass
    # base64
    if B64.match(raw):
        for pad in range(3):
            try:
                dec = base64.b64decode(re.sub(rb"\s+", b"", raw) + b"="*pad, validate=False)
                outs.append(("base64", dec.decode("utf-8", "ignore")))
            except:
                pass
    # base32
    if B32.match(raw):
        try:
            dec = base64.b32decode(re.sub(rb"\s+", b"", raw), casefold=True)
            outs.append(("base32", dec.decode("utf-8", "ignore")))
        except:
            pass
    # hex
    if HEX.match(raw):
        try:
            dec = binascii.unhexlify(re.sub(rb"\s+", b"", raw))
            outs.append(("hex", dec.decode("utf-8", "ignore")))
        except:
            pass
    return outs

def interesting(txt):
    if not txt:
        return False
    if "EnXp{" in txt:
        return True
    if score_text(txt) >= 0.85:
        return True
    return False

def decode_twochars(seq, zero="\u200b", one="\u200c"):
    bits = "".join("0" if ch==zero else "1" if ch==one else "" for ch in seq)
    return bits

def decode_fourchars(seq, mapping):
    bits = "".join(mapping.get(ch, "") for ch in seq)
    return bits

def run():
    s = load_input()
    zw = only_zw(s)
    print(f"Trovati {len(zw)} caratteri zero-width totali.")
    groups = split_by_separators(zw)
    print(f"Gruppi (separati da 2062/2063/2064): {len(groups)}")

    results = []

    # 2 simboli globali + per gruppo
    for zero, one in [(DATA2[0], DATA2[1]), (DATA2[1], DATA2[0])]:
        # globale
        bits = decode_twochars(zw, zero, one)
        for off, raw in bits_to_bytes(bits):
            for kind, txt in try_decoders(raw):
                if interesting(txt):
                    results.append(("2sym global", f"{ord(zero):04x}=0 {ord(one):04x}=1", off, kind, txt))
        # per gruppo
        bits_groups = "".join(decode_twochars(g, zero, one) + " " for g in groups)
        flat = bits_groups.replace(" ", "")
        for off, raw in bits_to_bytes(flat):
            for kind, txt in try_decoders(raw):
                if interesting(txt):
                    results.append(("2sym grouped", f"{ord(zero):04x}=0 {ord(one):04x}=1", off, kind, txt))

    # 4 simboli: tutte le permutazioni dei 2-bit
    for perm in itertools.permutations(["00","01","10","11"]):
        mp = dict(zip(DATA4, perm))
        bits = decode_fourchars(zw, mp)
        for off, raw in bits_to_bytes(bits):
            for kind, txt in try_decoders(raw):
                if interesting(txt):
                    results.append(("4sym global", str(mp), off, kind, txt))
        # per gruppo
        flat = "".join(decode_fourchars(g, mp) for g in groups)
        for off, raw in bits_to_bytes(flat):
            for kind, txt in try_decoders(raw):
                if interesting(txt):
                    results.append(("4sym grouped", str(mp), off, kind, txt))

    # dedup e stampa
    seen = set()
    for where, mp, off, kind, txt in results:
        key = (where, mp, off, kind, txt)
        if key in seen:
            continue
        seen.add(key)
        print("\n=== HIT ===")
        print(f"mode: {where} | map: {mp} | bit_offset: {off} | decode: {kind}")
        print(txt)

if __name__ == "__main__":
    run()