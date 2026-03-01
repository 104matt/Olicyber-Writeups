import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes
from skyfield.api import load
from skyfield.data import mpc
from skyfield.constants import GM_SUN_Pitjeva_2005_km3_s2 as GM_SUN
from fractions import Fraction

# ==========================================
# 0. Algoritmo LLL (Pure Python)
# ==========================================
def round_frac(f):
    """Arrotonda in modo sicuro frazioni con numeri enormi senza usare float()."""
    return (f.numerator + f.denominator // 2) // f.denominator

def gram_schmidt(B):
    """Calcola la base ortogonale e i coefficienti di Gram-Schmidt."""
    n = len(B)
    B_star = []
    mu = [[Fraction(0) for _ in range(n)] for _ in range(n)]
    
    for i in range(n):
        b_star_i = [Fraction(x) for x in B[i]]
        for j in range(i):
            dot_num = sum(B[i][k] * B_star[j][k] for k in range(len(B[i])))
            dot_den = sum(B_star[j][k] * B_star[j][k] for k in range(len(B[i])))
            if dot_den == 0:
                mu[i][j] = Fraction(0)
            else:
                mu[i][j] = Fraction(dot_num, dot_den)
                
            for k in range(len(B[i])):
                b_star_i[k] -= mu[i][j] * B_star[j][k]
        B_star.append(b_star_i)
    return B_star, mu

def lll_reduction(basis, delta=Fraction(3, 4)):
    """Riduzione LLL per un reticolo."""
    B = [list(row) for row in basis]
    n = len(B)
    B_star, mu = gram_schmidt(B)
    
    k = 1
    while k < n:
        # Step 1: Riduzione
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Fraction(1, 2):
                q = round_frac(mu[k][j])
                for i in range(len(B[k])):
                    B[k][i] -= q * B[j][i]
                # Ricalcoliamo GS (inefficiente per matrici enormi, ma per una 6x6 è istantaneo)
                B_star, mu = gram_schmidt(B)
        
        # Step 2: Condizione di Lovász
        norm_k = sum(x**2 for x in B_star[k])
        norm_k1 = sum(x**2 for x in B_star[k-1])
        
        if norm_k >= (delta - mu[k][k-1]**2) * norm_k1:
            k += 1
        else:
            # Swap
            B[k], B[k-1] = B[k-1], B[k]
            B_star, mu = gram_schmidt(B)
            k = max(1, k - 1)
            
    return B

# ==========================================
# 1. Brute-force the Transmission Time
# ==========================================
target_hash = "8b156702c993b9b5"
epoch_h, epoch_m, epoch_s = None, None, None

print("[*] Brute-forcing epoch time...")
for h in range(24):
    for m in range(60):
        for s in range(60):
            ts_str = f"{h:02d}:{m:02d}:{s:02d}"
            if hashlib.sha256(ts_str.encode()).hexdigest()[:16] == target_hash:
                epoch_h, epoch_m, epoch_s = h, m, s
                break
    if epoch_h is not None: break

print(f"[+] Recovered Time: {epoch_h:02d}:{epoch_m:02d}:{epoch_s:02d}")

# ==========================================
# 2. Recover LCG Parameters (a, b)
# ==========================================
print("[*] Loading comet data to derive LCG parameters...")
with load.open('CometEls.txt') as f:
    comets = mpc.load_comets_dataframe(f)
comets = comets.set_index('designation', drop=False)
row = comets.loc['1P/Halley']

ts = load.timescale()
t = ts.utc(2026, 1, 26, epoch_h, epoch_m, epoch_s)
eph = load('de421.bsp')
sun = eph['sun']
halley = sun + mpc.comet_orbit(row, ts, GM_SUN)

astrometric = sun.at(t).observe(halley)
x, y, z = astrometric.position.au

coord_string = f"{x:.10f}_{y:.10f}_{z:.10f}"
a = bytes_to_long(hashlib.sha512((coord_string + "_A").encode()).digest())
b = bytes_to_long(hashlib.sha512((coord_string + "_B").encode()).digest())

# ==========================================
# 3. Setup the Lattice & Solve HNP
# ==========================================
p = 10035410270612815279389330410121900529620495869479898461384631211745452304638984576440553552006414411373806160282016417372459090604747980402493134112626213
t_outputs = {
    0: 1129223615711367884405014640005288172041367198689786688285,
    4: 579514026315281536883405991880758556036404753274817543322,
    10: 1279648546218423539959079224022586160480305721841176089544,
    18: 1946366015289015629063708515503091199628321083313573104031,
    28: 3902208990133988884490762855871313599751888895643028675415
}
steps = [4, 10, 18, 28]

A_steps, B_steps = {}, {}
curr_A, curr_B = 1, 0
for i in range(1, 29):
    curr_A = (curr_A * a) % p
    curr_B = (curr_B * a + b) % p
    if i in steps:
        A_steps[i] = curr_A
        B_steps[i] = curr_B

K = 2**320

# Constructing the Lattice Basis come lista di liste 6x6
M = [[0] * 6 for _ in range(6)]

for i in range(4):
    M[i][i] = p
for i, step in enumerate(steps):
    M[4][i] = A_steps[step]
M[4][4] = 1

for i, step in enumerate(steps):
    Ci = (A_steps[step] * t_outputs[0] * K + B_steps[step] - t_outputs[step] * K) % p
    M[5][i] = Ci
M[5][5] = K

print("[*] Running custom LLL reduction to find short vectors...")
L = lll_reduction(M)

x_0 = None
for row_vec in L:
    if row_vec[-1] == K:
        x_0 = row_vec[-2]
        break
    elif row_vec[-1] == -K:
        x_0 = -row_vec[-2]
        break

if x_0 is None:
    print("[-] LLL failed. Could not find target vector.")
    exit()

print(f"[+] Recovered unknown lower bits of state 0: {x_0}")
S_0 = t_outputs[0] * K + x_0

# ==========================================
# 4. Fast-forward State & Decrypt
# ==========================================
state = S_0
# Loop 29 times to reach final_state
for _ in range(29):
    state = (a * state + b) % p

aes_key = hashlib.sha256(long_to_bytes(state)).digest()
iv = bytes.fromhex("ba04a327ffd0c69205ff5dcb5f463d9c")
ciphertext = bytes.fromhex("1879e4d0f174c9a6d2be99b6f632cc0f3ea89989e69dbd080761cb616b37d8eba37635de6c6475d741f69450c8259590")

cipher = AES.new(aes_key, AES.MODE_CBC, iv)
try:
    flag = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()
    print(f"\n[🚀] FLAG: {flag}")
except Exception as e:
    print(f"[-] Decryption failed: {e}")