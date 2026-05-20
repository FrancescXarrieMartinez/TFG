#!/usr/bin/env python3
"""
Bleichenbacher PKCS#1 v1.5 padding-oracle exploit (simple case) for the
Cryptopals 47 oracle adapter.

Invoked as: python3 exploit.py <oracle_path> <key> <ciphertext>
Recovers the message using ONLY padding validity (no private key). Drives the
oracle through the adapter's persistent `serve` mode, because the attack needs
tens of thousands of queries and a fresh process per query is far too slow.
Prints ONLY the recovered plaintext to stdout.
"""
import sys
import json
import base64
import subprocess


def ceil_div(a, b):
    return -(-a // b)


def floor_div(a, b):
    return a // b


class Oracle:
    """Persistent padding oracle over the adapter's `serve` stdin/stdout protocol."""

    def __init__(self, oracle_path, key, n, e):
        self.n, self.e = n, e
        self.proc = subprocess.Popen(
            [sys.executable, oracle_path, "serve", key],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )

    def __call__(self, c):
        blob = json.dumps({"n": format(self.n, "x"), "e": format(self.e, "x"), "c": format(c, "x")})
        wire = base64.b64encode(blob.encode()).decode()
        self.proc.stdin.write(wire + "\n")
        self.proc.stdin.flush()
        resp = json.loads(self.proc.stdout.readline())
        return bool(resp.get("plaintext_b64", ""))  # non-empty => padding starts 00 02

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


def _narrow(M, s, n, B):
    new = set()
    for (a, b) in M:
        r_lo = ceil_div(a * s - 3 * B + 1, n)
        r_hi = floor_div(b * s - 2 * B, n)
        for r in range(r_lo, r_hi + 1):
            lo = max(a, ceil_div(2 * B + r * n, s))
            hi = min(b, floor_div(3 * B - 1 + r * n, s))
            if lo <= hi:
                new.add((lo, hi))
    return list(new)


def bleichenbacher(n, e, c, oracle):
    k = (n.bit_length() + 7) // 8
    B = 2 ** (8 * (k - 2))
    M = [(2 * B, 3 * B - 1)]

    # Step 2a: smallest s >= ceil(n / 3B) producing a conforming c * s^e
    s = ceil_div(n, 3 * B)
    while not oracle((c * pow(s, e, n)) % n):
        s += 1
    M = _narrow(M, s, n, B)

    while True:
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0]
        if len(M) > 1:
            # Step 2b: more than one interval -> linear scan
            s += 1
            while not oracle((c * pow(s, e, n)) % n):
                s += 1
        else:
            # Step 2c: single interval -> O(log n) search over (r, s)
            a, b = M[0]
            r = ceil_div(2 * (b * s - 2 * B), n)
            found = False
            while not found:
                s = ceil_div(2 * B + r * n, b)
                s_max = floor_div(3 * B - 1 + r * n, a)
                while s <= s_max:
                    if oracle((c * pow(s, e, n)) % n):
                        found = True
                        break
                    s += 1
                if not found:
                    r += 1
        M = _narrow(M, s, n, B)


def main():
    oracle_path, key, ciphertext = sys.argv[1], sys.argv[2], sys.argv[3]
    blob = json.loads(base64.b64decode(ciphertext).decode())
    n, e, c = int(blob["n"], 16), int(blob["e"], 16), int(blob["c"], 16)

    oracle = Oracle(oracle_path, key, n, e)
    try:
        m = bleichenbacher(n, e, c, oracle)
    finally:
        oracle.close()

    k = (n.bit_length() + 7) // 8
    em = m.to_bytes(k, "big")
    # Strip PKCS#1 v1.5 (00 02 PS 00 M) -> M
    sep = em.find(b"\x00", 2)
    message = em[sep + 1:] if sep != -1 else em
    sys.stdout.write(message.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
