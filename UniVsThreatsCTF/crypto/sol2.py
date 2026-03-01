"""
Full solve for 'Celestial Body' CTF
Run in SageMath:  sage full_solve_sage.py
Or:               python3 full_solve_sage.py  (needs fpylll + skyfield)
"""
import hashlib, os
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ── Constants ─────────────────────────────────────────────────────────────────
P = 10035410270612815279389330410121900529620495869479898461384631211745452304638984576440553552006414411373806160282016417372459090604747980402493134112626213
TAP_Q = int("F518AA8781A8DF278ABA4E7D64B7CB9D49462353", 16)
TAP_G = int("A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5", 16)
TAP_P = int("B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371", 16)

STEPS  = [0, 4, 10, 18, 28]
T_VALS = [
    1129223615711367884405014640005288172041367198689786688285,
    579514026315281536883405991880758556036404753274817543322,
    1279648546218423539959079224022586160480305721841176089544,
    1946366015289015629063708515503091199628321083313573104031,
    3902208990133988884490762855871313599751888895643028675415,
]
IV  = bytes.fromhex("ba04a327ffd0c69205ff5dcb5f463d9c")
CT  = bytes.fromhex("1879e4d0f174c9a6d2be99b6f632cc0f3ea89989e69dbd080761cb616b37d8eba37635de6c6475d741f69450c8259590")
SIG_R = 289099664372750378797408625704893428920316669030
SIG_S = [952632243424303327990876772909325222302098148060,
         1272131170288215264283670079256435522443165444185,
         934252686529025066385350090392561039201739148363,
         727371275836726048686075601698051388854630211444,
         886522231176385982733156462394271368291922808313]
PRIME_BITS    = 512
TRUNCATE_BITS = 192
UNKNOWN_BITS  = PRIME_BITS - TRUNCATE_BITS  # 320 bits known, 192 unknown

# ── Step 1: Brute-force epoch time ────────────────────────────────────────────
print("[1] Brute-forcing epoch time...")
EPOCH_HASH = "8b156702c993b9b5"
epoch_time = None
for h in range(24):
    for m in range(60):
        for s in range(60):
            if hashlib.sha256(f"{h:02d}:{m:02d}:{s:02d}".encode()).hexdigest()[:16] == EPOCH_HASH:
                epoch_time = (h, m, s)
                break
        if epoch_time: break
    if epoch_time: break
HH, MM, SS = epoch_time
print(f"    Epoch time = {HH:02d}:{MM:02d}:{SS:02d}")

# ── Step 2: DSA nonce reuse → recover k ──────────────────────────────────────
print("[2] Recovering DSA nonce k...")
def msg_hash(step, t_val):
    return int(hashlib.sha1(f"TAP:sector_{step}:{t_val}".encode()).hexdigest(), 16) % TAP_Q

H = [msg_hash(s, t) for s, t in zip(STEPS, T_VALS)]
k = ((H[0] - H[1]) * pow(SIG_S[0] - SIG_S[1], -1, TAP_Q)) % TAP_Q
assert pow(TAP_G, k, TAP_P) % TAP_Q == SIG_R
print(f"    k = {k}")

# ── Step 3: Derive a, b from Halley's comet ───────────────────────────────────
print("[3] Deriving LCG seed from Halley's comet position...")
from skyfield.api import load as sky_load
from skyfield.data import mpc
from skyfield.constants import GM_SUN_Pitjeva_2005_km3_s2 as GM_SUN

if not os.path.exists('CometEls.txt'):
    import urllib.request
    urllib.request.urlretrieve(
        "https://minorplanetcenter.net/iau/Ephemerides/Comets/Soft00Cmt.txt",
        'CometEls.txt')

with sky_load.open('CometEls.txt') as f:
    comets = mpc.load_comets_dataframe(f)
comets = comets.set_index('designation', drop=False)
row = comets.loc['1P/Halley']
ts_sf  = sky_load.timescale()
t_sf   = ts_sf.utc(2026, 1, 26, HH, MM, SS)
eph    = sky_load('de421.bsp')
sun    = eph['sun']
halley = sun + mpc.comet_orbit(row, ts_sf, GM_SUN)
ax, ay, az = sun.at(t_sf).observe(halley).position.au
coord_str = f"{ax:.10f}_{ay:.10f}_{az:.10f}"
print(f"    Halley pos (AU): x={ax:.6f}, y={ay:.6f}, z={az:.6f}")
a = bytes_to_long(hashlib.sha512((coord_str + "_A").encode()).digest())
b = bytes_to_long(hashlib.sha512((coord_str + "_B").encode()).digest())
print(f"    a = {a}")
print(f"    b = {b}")

# ── Step 4: LLL lattice attack on truncated LCG ───────────────────────────────
print("[4] Running LLL lattice attack...")

W = 1 << TRUNCATE_BITS  # 2^192

def multi_step(n_steps, a, b, p):
    """Returns (An, Bn) such that state_{+n} = An*state + Bn mod p"""
    An, Bn = 1, 0
    for _ in range(n_steps):
        An = (a * An) % p
        Bn = (a * Bn + b) % p
    return An, Bn

N = len(STEPS)
An_list, Bn_list = [], []
for i in range(N - 1):
    An, Bn = multi_step(STEPS[i+1] - STEPS[i], a, b, P)
    An_list.append(An)
    Bn_list.append(Bn)

# state_{i+1} = An_i * state_i + Bn_i  mod P
# state_i = T_VALS[i]*W + e_i,  0 <= e_i < W
# => An_i*(T_VALS[i]*W + e_i) + Bn_i = T_VALS[i+1]*W + e_{i+1}  mod P
# => An_i*e_i - e_{i+1} = C_i  mod P
# where C_i = T_VALS[i+1]*W - An_i*T_VALS[i]*W - Bn_i  mod P
C = [(T_VALS[i+1]*W - An_list[i]*T_VALS[i]*W - Bn_list[i]) % P for i in range(N-1)]

# Build lattice (Kannan embedding):
# Unknowns: e_0..e_4 (bounded by W=2^192), k_0..k_3 (modular multipliers), 1 (target)
# Row structure:
#   First N rows:   e_i basis   (diagonal W)
#   Next N-1 rows:  An_i*e_i - e_{i+1} - k_i*P = C_i
# We embed target C as an extra row with a small penalty weight.

try:
    from sage.all import Matrix, ZZ, vector
    USE_SAGE = True
except ImportError:
    USE_SAGE = False

if USE_SAGE:
    from sage.all import Matrix, ZZ, vector

    dim = N + (N-1)
    M = Matrix(ZZ, dim + 1, dim + 1)

    # e_i scaled columns
    for i in range(N):
        M[i, i] = W

    # constraint rows
    for i in range(N-1):
        M[N+i, i]   =  An_list[i]
        M[N+i, i+1] = -1
        M[N+i, N+i] =  P

    # Target row (Kannan embedding)
    for i in range(N-1):
        M[dim, N+i] = C[i]     # the known RHS
    M[dim, dim] = 1            # embedding weight

    print("    Running LLL...")
    L = M.LLL()

    # Search reduced rows for our solution
    flag_found = False
    for row_vec in L.rows():
        if abs(row_vec[-1]) != 1:
            continue
        sign = int(row_vec[-1])
        e = [sign * int(row_vec[i]) for i in range(N)]
        if all(0 <= ei < W for ei in e):
            # Recover full state at step 28
            state_28 = (T_VALS[4] * W + e[4]) % P
            # Final state: one more LCG step after step 28
            final_state = (a * state_28 + b) % P
            aes_key = hashlib.sha256(long_to_bytes(final_state)).digest()
            cipher  = AES.new(aes_key, AES.MODE_CBC, IV)
            try:
                flag = unpad(cipher.decrypt(CT), 16)
                print(f"\n[+] FLAG: {flag.decode()}")
                flag_found = True
                break
            except Exception:
                pass

    if not flag_found:
        print("[-] No valid flag found — check a/b derivation or lattice setup.")
else:
    print("[!] SageMath not available. Run this script with: sage full_solve_sage.py")