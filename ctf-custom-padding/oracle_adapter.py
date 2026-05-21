#!/usr/bin/env python3
"""
Oracle adapter for a self-authored CUSTOM-PADDING CBC padding-oracle CTF -- VULNERABLE.

Teaching example in the spirit of HackTheBox "Fibopadcci": a CBC padding oracle whose
padding scheme is NOT PKCS#7. We keep standard AES-128-CBC (we do NOT reproduce
Fibopadcci's IGE/AES-ECB cipher mode or its source) and vary only the PADDING RULE, to
show that the Vaudenay byte-recovery attack generalizes to any position-dependent padding
scheme -- the exploit only has to adapt which byte values it forges.

Custom padding ("Fibonacci length-tagged", ISO 10126 lineage), block size 16:
  A valid padding of length N (1..16) occupies the last N bytes of the block:
    - distance 0 (the last byte) = N                      (the length tag)
    - distance j (1..N-1)        = FIB[j]                 (a fixed deterministic prefix)
  where FIB is the Fibonacci sequence mod 256 indexed by distance from the end.
  Validity: read the last byte N; valid iff 1<=N<=16 and the N-1 preceding bytes equal
  FIB[1..N-1]. (PKCS#7 would instead require all N trailing bytes to equal N.)

Usage: python3 oracle_adapter.py <command> [args...]
  encrypt <plaintext> <key>   - custom-pad, AES-128-CBC encrypt; emits base64(IV||ct)
  decrypt <state> <key>       - AES-128-CBC decrypt; report ONLY custom-padding validity
  serve   <key>               - persistent oracle: one base64 state per stdin line,
                                one JSON response per stdout line (use for the attack)

Wire format: base64( IV[16] || ciphertext ). plaintext_b64 non-empty => padding VALID;
empty string => padding INVALID.
"""

import os
import sys
import json
import time
import base64
from Crypto.Cipher import AES

BLOCK_SIZE = 16

# FIB[d] = Fibonacci mod 256 indexed by distance-from-end d (1..BLOCK_SIZE-1).
# FIB[0] is unused: distance 0 holds the length tag N, not a Fibonacci value.
FIB = [0] * BLOCK_SIZE
FIB[1] = 1
FIB[2] = 1
for _d in range(3, BLOCK_SIZE):
    FIB[_d] = (FIB[_d - 1] + FIB[_d - 2]) % 256


def fib_pad(msg):
    """Append custom padding so len is a multiple of BLOCK_SIZE (full block if already aligned)."""
    n = BLOCK_SIZE - (len(msg) % BLOCK_SIZE)  # 1..BLOCK_SIZE
    padding = bytes((n if dist == 0 else FIB[dist]) for dist in range(n - 1, -1, -1))
    return msg + padding


def fib_unpad(raw):
    """THE PADDING RULE. Returns the message on valid padding, else None."""
    if not raw:
        return None
    n = raw[-1]
    if n < 1 or n > BLOCK_SIZE or n > len(raw):
        return None
    for dist in range(1, n):  # check the deterministic Fibonacci prefix
        if raw[len(raw) - 1 - dist] != FIB[dist]:
            return None
    return raw[:-n]


def _log_oracle(valid, elapsed_ms):
    """Append one JSON line per decrypt call when ORACLE_LOG is set (reward telemetry)."""
    path = os.environ.get("ORACLE_LOG")
    if not path:
        return
    try:
        with open(path, "a") as f:
            f.write(json.dumps({"valid": bool(valid), "elapsed_ms": elapsed_ms}) + "\n")
    except OSError:
        pass


def _padding_oracle(state, key):
    """AES-128-CBC decrypt then the custom Fibonacci padding check. Returns
    base64(message) on valid padding, "" on invalid padding / any failure."""
    try:
        combined = base64.b64decode(state)
    except Exception:
        return ""
    if len(combined) < 2 * BLOCK_SIZE or (len(combined) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        return ""
    iv = combined[:BLOCK_SIZE]
    ct = combined[BLOCK_SIZE:]
    raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)  # no automatic unpadding
    msg = fib_unpad(raw)
    if msg is None:
        return ""
    return base64.b64encode(msg if msg else b"\x00").decode()  # sentinel for empty-but-valid


def main(argv):
    if len(argv) < 2:
        sys.stderr.write("Usage: python3 oracle_adapter.py <command> [args...]\n")
        sys.exit(1)

    command = argv[1]
    sys.stderr.write("command=%s\n" % command)

    if command == "encrypt":
        if len(argv) != 4:
            sys.stderr.write("Usage: encrypt <plaintext> <key>\n")
            sys.exit(1)
        plaintext = argv[2].encode()
        key = argv[3].encode()  # AES-128 key (16 bytes)
        iv = os.urandom(BLOCK_SIZE)
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(fib_pad(plaintext))
        print(json.dumps({"status": "success", "ciphertext": base64.b64encode(iv + ct).decode()}))

    elif command == "decrypt":
        if len(argv) != 4:
            sys.stderr.write("Usage: decrypt <state> <key>\n")
            sys.exit(1)
        key = argv[3].encode()
        start = time.time()
        result_b64 = _padding_oracle(argv[2], key)
        _log_oracle(bool(result_b64), (time.time() - start) * 1000.0)
        print(json.dumps({"status": "success", "plaintext_b64": result_b64}))

    elif command == "serve":
        if len(argv) != 3:
            sys.stderr.write("Usage: serve <key>\n")
            sys.exit(1)
        key = argv[2].encode()
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            start = time.time()
            result_b64 = _padding_oracle(line, key)
            _log_oracle(bool(result_b64), (time.time() - start) * 1000.0)
            sys.stdout.write(json.dumps({"status": "success", "plaintext_b64": result_b64}) + "\n")
            sys.stdout.flush()

    else:
        sys.stderr.write("Unknown command: %s\n" % command)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
