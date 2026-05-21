#!/usr/bin/env python3
"""
Padding-oracle exploit (Vaudenay byte-recovery) for the self-authored DES-CBC CTF
oracle. Identical to the AES serve-driven exploits except BLOCK_SIZE = 8 (DES) instead
of 16 (AES) -- the algorithm is block-size agnostic.

Invoked as: python3 exploit.py <oracle_path> <key> <ciphertext>
State = base64(IV[8] || ciphertext). Recovers the plaintext without the key, driving the
adapter's persistent `serve` mode. Prints ONLY the recovered plaintext to stdout.
"""
import sys
import json
import base64
import subprocess

BLOCK_SIZE = 8  # DES block size (vs 16 for AES)


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
    zeroing = [0] * BLOCK_SIZE
    for pad_val in range(1, BLOCK_SIZE + 1):
        prev = [pad_val ^ b for b in zeroing]
        for cand in range(256):
            prev[-pad_val] = cand
            if oracle(prev, block):
                if pad_val == 1:
                    prev[-2] ^= 1
                    if not oracle(prev, block):
                        prev[-2] ^= 1
                        continue
                    prev[-2] ^= 1
                break
        else:
            raise Exception("no valid padding byte found at position %d" % pad_val)
        zeroing[-pad_val] = cand ^ pad_val
    return zeroing


def full_attack(iv, ct, oracle):
    blocks = [iv] + [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    out = b""
    for i in range(1, len(blocks)):
        z = single_block_attack(blocks[i], oracle)
        out += bytes(a ^ b for a, b in zip(blocks[i - 1], z))
    return out


def pkcs7_unpad(d):
    if not d:
        return d
    p = d[-1]
    if 1 <= p <= BLOCK_SIZE and d[-p:] == bytes([p]) * p:
        return d[:-p]
    return d


def main():
    oracle_path, key, state = sys.argv[1], sys.argv[2], sys.argv[3]
    raw = base64.b64decode(state)
    iv, ct = raw[:BLOCK_SIZE], raw[BLOCK_SIZE:]
    oracle = Oracle(oracle_path, key)
    try:
        rec = full_attack(iv, ct, oracle)
    finally:
        oracle.close()
    sys.stdout.write(pkcs7_unpad(rec).decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
