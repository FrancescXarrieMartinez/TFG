#!/usr/bin/env python3
"""
Padding-oracle exploit (Vaudenay byte-recovery) for the self-authored custom-padding CBC
oracle. This is the SAME attack as the PKCS#7 entries -- the ONLY adaptation is the
`target()` function describing which plaintext bytes a valid padding requires.

  PKCS#7 padding of length N : every one of the last N bytes equals N.
  This challenge's padding     : last byte (distance 0) = N; the preceding bytes
                                 (distance 1..N-1) equal FIB[1..N-1] (Fibonacci mod 256).

So to recover the byte at distance d we force a padding of length N=d+1: we already know
the cipher's intermediate D(block) for distances 0..d-1, so we set the manipulated previous
block to make those plaintext bytes equal their required targets, then brute-force the
distance-d byte until the oracle accepts -- at which point that plaintext byte equals
target(N, d), revealing the intermediate. Block-size and padding-rule are just parameters.

Invoked as: python3 exploit.py <oracle_path> <key> <ciphertext>
State = base64(IV[16] || ciphertext). Drives the adapter's persistent `serve` mode.
Prints ONLY the recovered plaintext to stdout.
"""
import sys
import json
import base64
import subprocess

BLOCK_SIZE = 16

# Same Fibonacci-mod-256 table the oracle uses (FIB[d] for distance d = 1..BLOCK_SIZE-1).
FIB = [0] * BLOCK_SIZE
FIB[1] = 1
FIB[2] = 1
for _d in range(3, BLOCK_SIZE):
    FIB[_d] = (FIB[_d - 1] + FIB[_d - 2]) % 256


def target(n, dist):
    """Plaintext byte required at `dist` from the end for a VALID length-n padding.
    (PKCS#7 would be `return n` for every dist; here only distance 0 is the length tag.)"""
    return n if dist == 0 else FIB[dist]


class Oracle:
    def __init__(self, oracle_path, key):
        self.proc = subprocess.Popen(
            [sys.executable, oracle_path, "serve", key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )

    def __call__(self, prev, block):
        state = base64.b64encode(bytes(prev) + bytes(block)).decode()
        self.proc.stdin.write(state + "\n")
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        return bool(resp.get("plaintext_b64", ""))  # non-empty => valid padding

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def single_block_attack(block, oracle):
    """Recover inter[dist] = D(block) at each distance from the end."""
    inter = [0] * BLOCK_SIZE
    for n in range(1, BLOCK_SIZE + 1):           # forge a valid padding of length n
        prev = [0] * BLOCK_SIZE
        # Pin the already-known distances 0..n-2 to their required target bytes.
        for dist in range(0, n - 1):
            prev[BLOCK_SIZE - 1 - dist] = inter[dist] ^ target(n, dist)
        attack_dist = n - 1
        pos = BLOCK_SIZE - 1 - attack_dist
        for cand in range(256):
            prev[pos] = cand
            if oracle(prev, block):
                if n == 1:
                    # Disambiguate genuine length-1 (last byte 0x01, no prefix checked) from an
                    # accidental longer match: flip a far byte; length-1 ignores it -> still valid.
                    prev[BLOCK_SIZE - 2] ^= 1
                    still = oracle(prev, block)
                    prev[BLOCK_SIZE - 2] ^= 1
                    if not still:
                        continue
                inter[attack_dist] = cand ^ target(n, attack_dist)
                break
        else:
            raise Exception("no valid padding found at length %d" % n)
    return inter


def full_attack(iv, ct, oracle):
    blocks = [iv] + [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    out = b""
    for i in range(1, len(blocks)):
        inter = single_block_attack(blocks[i], oracle)
        prev = blocks[i - 1]
        # plaintext byte at position p = inter[distance] XOR prev[p]
        out += bytes(inter[BLOCK_SIZE - 1 - p] ^ prev[p] for p in range(BLOCK_SIZE))
    return out


def fib_unpad(raw):
    if not raw:
        return raw
    n = raw[-1]
    if n < 1 or n > BLOCK_SIZE or n > len(raw):
        return raw
    for dist in range(1, n):
        if raw[len(raw) - 1 - dist] != FIB[dist]:
            return raw
    return raw[:-n]


def main():
    oracle_path, key, state = sys.argv[1], sys.argv[2], sys.argv[3]
    raw = base64.b64decode(state)
    iv, ct = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
    oracle = Oracle(oracle_path, key)
    try:
        rec = full_attack(iv, ct, oracle)
    finally:
        oracle.close()
    sys.stdout.write(fib_unpad(rec).decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
