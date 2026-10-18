# Paradise (Cryptography): Write-up

The challenge used Python's `random.Random`, seeded with eight random bytes. It generated a 32-bit secret first, then leaked the upper 16 bits of each of the next 966 outputs. We needed to recover the original seed and the secret to obtain the flag.

## 1. Understand the challenge

The source, `chall.py`, followed this sequence:

1. Generate an eight-byte seed with `randbytes(8)`.
2. Initialize `rng = Random(seed)`.
3. Generate `secret = rng.getrandbits(32)`.
4. Print 966 values of `rng.getrandbits(32) >> 16`.
5. Ask for the seed in hexadecimal and the secret as an integer.
6. Return the flag when both answers match.

The first output is the hidden secret. The first leaked value therefore corresponds to output index 1, not index 0. Keeping that offset correct matters when constructing the equations.

## 2. Recover state from truncated outputs

MT19937's twist and tempering operations are linear over $GF(2)$. We represent each bit of its 624-word state as a symbolic variable, express the generated outputs in terms of those variables, and add an equation for each leaked bit.

There are `624 * 32 = 19,968` symbolic state bits, while the leaks provide `966 * 16 = 15,456` bit equations. The solver does not recover the entire state from these equations alone. Gaussian elimination identifies fully determined state words, and a sufficiently long contiguous segment allows the seed-inversion step to proceed.

The solver models the in-place twist, applies the tempering transformations, and builds equations only for output bits 16 through 31. It skips output index 0 because that output is the secret.

## 3. Invert Python's byte-seed initialization

For this byte-seed initialization, Python expands the seed using `seed + sha512(seed)`. Eight seed bytes and 64 digest bytes form 72 bytes, represented as 18 little-endian 32-bit words for `init_by_array`.

The solver reverses the initialization operations using recovered consecutive state words. It gathers candidates for each of the 18 key words and checks that repeated candidates agree. After reconstructing the key integer, it extracts the original eight-byte seed and checks the remaining 64 bytes against `sha512(seed)`.

Finally, a local `random.Random(seed)` regenerates the first 32-bit output as the secret and checks whether subsequent truncated outputs reproduce all the supplied leaks. The SHA-512 and leak checks provide independent validation of the recovered seed.

## 4. Solver

The code below restores indentation and line wrapping from the supplied write-up. It uses Python 3 and only the standard library. This formatting repair was syntax-checked; the original challenge was not rerun while preparing this version.

Save this block locally as `solve.py`:

```python
import sys
import re
import random
from hashlib import sha512

N, M = 624, 397
NV = N * 32
MAT = 0x9908b0df
M32 = 0xffffffff


# Symbolic MT19937 over GF(2).
def twist_word(up, lo, other):
    y = [lo[b] if b < 31 else up[31] for b in range(32)]
    out = []
    for b in range(32):
        v = other[b]
        if b < 31:
            v ^= y[b + 1]
        if (MAT >> b) & 1:
            v ^= y[0]
        out.append(v)
    return out


def temper(y):
    y = [y[b] ^ (y[b + 11] if b + 11 < 32 else 0) for b in range(32)]
    m2, m3 = 0x9d2c5680, 0xefc60000
    y = [y[b] ^ ((y[b - 7] if b >= 7 else 0) if (m2 >> b) & 1 else 0)
         for b in range(32)]
    y = [y[b] ^ ((y[b - 15] if b >= 15 else 0) if (m3 >> b) & 1 else 0)
         for b in range(32)]
    y = [y[b] ^ (y[b + 18] if b + 18 < 32 else 0) for b in range(32)]
    return y


def symbolic_outputs(nout):
    cur = [[1 << (w * 32 + b) for b in range(32)] for w in range(N)]
    words = []
    while len(words) < nout:
        cur = list(cur)
        for k in range(N):
            cur[k] = twist_word(cur[k], cur[(k + 1) % N], cur[(k + M) % N])
        words += cur
    return [temper(w) for w in words[:nout]]


def solve_known_words(leak):
    outs = symbolic_outputs(len(leak) + 1)
    piv = {}
    for k, val in enumerate(leak, start=1):  # Output index 0 is the secret.
        for b in range(16, 32):
            r = outs[k][b] | (((val >> (b - 16)) & 1) << NV)
            while r & ((1 << NV) - 1):
                p = (r & -r).bit_length() - 1
                if p in piv:
                    r ^= piv[p]
                else:
                    piv[p] = r
                    break
            else:
                if r:
                    raise SystemExit("inconsistent system (wrong input?)")

    for p in sorted(piv, reverse=True):  # Back-substitute to RREF.
        r = piv[p]
        while True:
            rest = (r & ((1 << NV) - 1)) >> (p + 1)
            hit = None
            while rest:
                low = (rest & -rest).bit_length() - 1
                if p + 1 + low in piv:
                    hit = p + 1 + low
                    break
                rest &= rest - 1
            if hit is None:
                break
            r ^= piv[hit]
        piv[p] = r

    known = {}
    for p, r in piv.items():
        if (r & ((1 << NV) - 1)) == (1 << p):
            known[p] = (r >> NV) & 1
    C = {}
    for w in range(N):
        if all((w * 32 + b) in known for b in range(32)):
            C[w] = sum(known[w * 32 + b] << b for b in range(32))
    return C


# Invert init_by_array.
def init_genrand(s=19650218):
    mt = [s]
    for i in range(1, N):
        mt.append((1812433253 * (mt[-1] ^ (mt[-1] >> 30)) + i) & M32)
    return mt


f = lambda x: x ^ (x >> 30)


def key_from_state(C):
    B = init_genrand()
    cand = {}
    for i in range(3, N):
        if i in C and i - 1 in C and i - 2 in C:
            A = lambda t: ((C[t] + t) ^ (f(C[t - 1]) * 1566083941)) & M32
            j = (i - 1) % 18
            k = (A(i) - (B[i] ^ (f(A(i - 1)) * 1664525)) - j) & M32
            cand.setdefault(j, []).append(k)
    key = []
    for j in range(18):
        if j not in cand:
            raise SystemExit(f"key word {j} not recovered (known run too short)")
        vals = set(cand[j])
        if len(vals) != 1:
            raise SystemExit(f"inconsistent key word {j}: {vals}")
        key.append(vals.pop())
    return key


def main():
    if len(sys.argv) > 1:
        txt = open(sys.argv[1], encoding="utf-8", errors="ignore").read()
    else:
        print("Paste the server output (the [...] list), then press "
              "Ctrl+Z + Enter (Windows) / Ctrl+D (Linux):")
        txt = sys.stdin.read()
    m = re.search(r"\[([\d,\s]+)\]", txt)
    if not m:
        raise SystemExit("could not find the [...] list of numbers in the input")
    leak = [int(x) for x in re.findall(r"\d+", m.group(1))]
    if len(leak) < 900:
        raise SystemExit(f"only {len(leak)} values found, expected 966 "
                         "- was the list pasted completely?")
    print(f"[+] {len(leak)} leaked values")
    C = solve_known_words(leak)
    ws = sorted(C)
    print(f"[+] fully determined state words: {len(ws)} "
          f"(indices {ws[0]}..{ws[-1]})")
    key = key_from_state(C)
    a = sum(k << (32 * i) for i, k in enumerate(key))
    seed = (a >> 512).to_bytes(8, "big")
    assert (a & ((1 << 512) - 1)).to_bytes(64, "big") == sha512(seed).digest(), "sha512 check failed"
    r = random.Random(seed)
    secret = r.getrandbits(32)
    ok = all((r.getrandbits(32) >> 16) == v for v in leak)
    print(f"[+] seed (hex): {seed.hex()}")
    print(f"[+] secret : {secret}")
    print(f"[+] reproduces all leaked values: {ok}")


if __name__ == "__main__":
    main()
```

Capture the complete server output, including the bracketed list, in `leak.txt`, then run:

```bash
python3 solve.py leak.txt
```

The solver prints the seed in hexadecimal, the secret, and whether the seed reproduces the leaks. Submit the values from the same server session that produced the list.

## 5. Automation excerpt

The supplied `auto.py` excerpt contains a recovery helper and wrappers for a remote socket or a local `chall.py` process. It does not include the entry point that parses the server list, calls `recover`, and submits the answers. The following is the restored excerpt, not a complete standalone automation script. It expects the preceding solver to be saved as `solve.py`.

```python
import sys
import socket
import subprocess
import random
from hashlib import sha512
import solve


def recover(leak):
    C = solve.solve_known_words(leak)
    key = solve.key_from_state(C)
    a = sum(k << (32 * i) for i, k in enumerate(key))
    seed = (a >> 512).to_bytes(8, "big")
    assert (a & ((1 << 512) - 1)).to_bytes(64, "big") == sha512(seed).digest()
    return seed.hex(), random.Random(seed).getrandbits(32)


class Remote:
    def __init__(self, host, port):
        self.s = socket.create_connection((host, int(port)))
        self.buf = b""

    def read_until(self, marker, timeout=60):
        self.s.settimeout(timeout)
        while marker not in self.buf:
            d = self.s.recv(65536)
            if not d:
                break
            self.buf += d
        i = self.buf.find(marker)
        i = len(self.buf) if i < 0 else i + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out.decode(errors="ignore")

    def send(self, line):
        self.s.sendall(line.encode() + b"\n")

    def read_rest(self):
        self.s.settimeout(5)
        out = self.buf
        try:
            while True:
                d = self.s.recv(65536)
                if not d:
                    break
                out += d
        except Exception:
            pass
        return out.decode(errors="ignore")


class Local:
    def __init__(self):
        self.p = subprocess.Popen(
            [sys.executable, "-u", "chall.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        self.buf = b""

    def read_until(self, marker, timeout=60):
        while marker not in self.buf:
            c = self.p.stdout.read1(65536)
            if not c:
                break
            self.buf += c
        i = self.buf.find(marker)
        i = len(self.buf) if i < 0 else i + len(marker)
        out, self.buf = self.buf[:i], self.buf[i:]
        return out.decode(errors="ignore")

    def send(self, line):
        self.p.stdin.write(line.encode() + b"\n")
        self.p.stdin.flush()

    def read_rest(self):
        return (self.buf + self.p.stdout.read()).decode(errors="ignore")

    def main():
        io = Remote(sys.argv[1], sys.argv[2]) if len(sys.argv) >= 3 else Local()
        txt = io.read_until(b"Seed (hex): ")
        m = re.search(r"\[([\d,\s]+)\]", txt)
        leak = [int(x) for x in re.findall(r"\d+", m.group(1))]
        print(f"[+] got {len(leak)} leaked values, solving ...")
        seed_hex, secret = recover(leak)
        print(f"[+] seed={seed_hex} secret={secret}")
        io.send(seed_hex)
        io.read_until(b"Secret: ")
        io.send(str(secret))
        print(io.read_rest())
    
    if __name__ == "__main__":
        main()
```

## 6. Recorded execution

The supplied solve record used this endpoint:

```bash
nc -vz koala.nexsec.my 39310
python3 auto.py koala.nexsec.my 39310
```

The second command refers to the complete automation script used during the solve; its entry point was not included in the supplied excerpt.

The preserved output includes:

```text
[+] got 966 leaked values, solving ...
[+] seed=00993c3b7cca9314 secret=1517159185
```

These values belong to the recorded session. A new session can use a different seed and secret. The captured flag output in the terminal excerpt was truncated, so the full flag below is transcribed from the supplied flag-retrieval section. A whitespace break inside its hexadecimal suffix has been removed.

## 7. Flag

```text
nexsec26{w0w_y0u_already_kn0w_Mersenne_Twister_nice_11a627b590f92d015c4663bfd6271533318a6d2a6e231d98032debc34230b0e2}
```
