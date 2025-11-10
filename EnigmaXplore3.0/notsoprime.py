#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Solver RSA per CTF con due moduli N1, N2 e un ciphertext c.
# Prova:
# - GCD(N1, N2) per trovare un primo condiviso (common prime).
# - Decrypt con N1, N2 e anche con N1*N2 (multi-prime) provando e in {3,5,17,65537}.
# - Håstad/small-e: radice intera esatta di c per e piccoli.
#
# Uso:
#   python3 solve_rsa_ctf.py
#
# Nota: se serve, modifica E_CANDIDATES o i valori N1, N2, c qui sotto.

from math import gcd, isqrt

# Dati della challenge (incolla/aggiorna qui se necessario)
N1 = 84170970098395536507903989168206011510088784721448747637294030328409639412673414236606476359889460248328091580495194871481849393422443719582034674050193208369146158029884224275946080917524741462950967082489509630880340870179556067104149984224772077085852604152486548008143421946361083009979343721711113624551
N2 = 72956521008325634279863020617569530467452774339429940337609924095020241277996570762583210792032920042185687762660635691377258915077525620987174120321400836312974212535370792547381451332577141344640787436774984455625136747998285663124740705910045224324501317583236714134697117449374328695356096707238750218749
c = 4544691077090994242597378078856406595614438258896803012079565162646093886636066525667618436410411748305287078382236569140369137492371669110237220055776614272552374629859313649813307313181821444765238229113107656661914379777247056758005723371583375397223110705918972256154256670473604644633551054416919796138757705

# Esponenti pubblici tipici da provare
E_CANDIDATES = [3, 5, 17, 65537]

# ---------------------------------------------------------------------------

def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def invmod(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        return None
    return x % m

def int_to_bytes(n, min_len=0):
    if n == 0:
        b = b"\x00"
    else:
        blen = (n.bit_length() + 7) // 8
        b = n.to_bytes(blen, "big")
    if len(b) < min_len:
        b = (b"\x00" * (min_len - len(b))) + b
    return b

def is_printable(b):
    # Heuristica semplice per testo ASCII/flag
    if not b:
        return False
    printable = bytes(range(32, 127)) + b"\n\r\t"
    score = sum(ch in printable for ch in b) / len(b)
    return score > 0.80 or any(tag in b for tag in (b"CTF{", b"flag{", b"HTB{", b"picoCTF{", b"RS{", b"GH{"))

def pkcs1_unpad(b):
    # Tentativo semplice PKCS#1 v1.5: 0x00 0x02 ... 0x00 data (o 0x01)
    if len(b) < 11:
        return b
    if b[0] == 0x00 and b[1] in (0x02, 0x01):
        try:
            sep = b.index(0x00, 2)
            return b[sep+1:]
        except ValueError:
            return b
    return b

def miller_rabin(n):
    # Probable-prime test (basi fisse; deterministico per 64-bit, prob. per big int)
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29]
    for p in small_primes:
        if n % p == 0:
            return n == p
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1
    bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    for a in bases:
        if a % n == 0:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def nth_root_floor(n, r):
    if n < 0 and r % 2 == 0:
        raise ValueError("even root of negative number")
    if r == 2:
        return isqrt(n)
    lo, hi = 0, 1
    while hi ** r <= n:
        hi <<= 1
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        p = mid ** r
        if p == n:
            return mid
        if p < n:
            lo = mid
        else:
            hi = mid
    return lo

def try_decrypt_with_factors(N, p, q, e_list, c_val):
    results = []
    phi = (p - 1) * (q - 1)
    for e in e_list:
        d = invmod(e, phi)
        if d is None:
            continue
        m = pow(c_val % N, d, N)
        mb = int_to_bytes(m, min_len=(N.bit_length() + 7) // 8)
        mb_unpadded = pkcs1_unpad(mb).lstrip(b"\x00")
        candidates = [(mb, "raw"), (mb_unpadded, "unpadded")]
        for data, kind in candidates:
            if is_printable(data):
                results.append((e, kind, data))
    return results

# ---------------------------------------------------------------------------

def main():
    found_any = False

    print("[*] GCD(N1, N2) per fattorizzare (common prime attack)...")
    g = gcd(N1, N2)
    if g > 1:
        print(f"[+] gcd(N1, N2) = {g} (fattorizzazione riuscita)")
        # Decrypt con N1
        p1 = g
        q1 = N1 // g
        print("[*] Provo con N1 ...")
        r1 = try_decrypt_with_factors(N1, p1, q1, E_CANDIDATES, c)
        for e, kind, data in r1:
            found_any = True
            print(f"[OK] N1 con e={e}, {kind}:")
            try:
                print(data.decode())
            except:
                print(repr(data))

        # Decrypt con N2
        p2 = g
        q2 = N2 // g
        print("[*] Provo con N2 ...")
        r2 = try_decrypt_with_factors(N2, p2, q2, E_CANDIDATES, c)
        for e, kind, data in r2:
            found_any = True
            print(f"[OK] N2 con e={e}, {kind}:")
            try:
                print(data.decode())
            except:
                print(repr(data))
    else:
        print("[-] Nessun primo condiviso fra N1 e N2.")

    print("[*] Verifica primalità probabile di N1 e N2 ...")
    n1_prime = miller_rabin(N1)
    n2_prime = miller_rabin(N2)
    print(f"    N1 is prime? {n1_prime}")
    print(f"    N2 is prime? {n2_prime}")

    if n1_prime and n2_prime:
        N = N1 * N2
        print("[*] Provo decriptare con N = N1 * N2 (multi-prime RSA) ...")
        r = try_decrypt_with_factors(N, N1, N2, E_CANDIDATES, c)
        for e, kind, data in r:
            found_any = True
            print(f"[OK] N1*N2 con e={e}, {kind}:")
            try:
                print(data.decode())
            except:
                print(repr(data))
    else:
        print("[-] Non sembra un caso N = N1*N2 con N1 e N2 primi (o test non conclusivo).")

    print("[*] Controllo small-e (Håstad) cercando radice intera esatta di c ...")
    for e in [3, 5, 7]:
        root = nth_root_floor(c, e)
        if root ** e == c:
            mb = int_to_bytes(root)
            if is_printable(mb):
                found_any = True
                print(f"[OK] Small-e exact root con e={e}:")
                try:
                    print(mb.decode())
                except:
                    print(repr(mb))

    if not found_any:
        print("[-] Nessun plaintext plausibile trovato automaticamente.")
        print("Suggerimenti:")
        print("- Conferma l'esponente pubblico e (spesso 65537).")
        print("- Specifica quale modulo è stato usato (N1, N2, oppure N1*N2).")
        print("- Indica se c ha padding (PKCS#1 v1.5, OAEP) o se è plain.")
        print("- Se hai un file output.txt con N1, N2, c, incollali sopra e rilancia.")

if __name__ == "__main__":
    main()