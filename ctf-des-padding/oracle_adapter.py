#!/usr/bin/env python3
"""
Oracle adapter for a self-authored DES-CBC padding-oracle CTF challenge -- VULNERABLE.

Teaching example in the spirit of HackTheBox "I know Mag1k" (a CBC padding oracle on
an encrypted session cookie). This is our own implementation of the vulnerability
class -- NOT a reproduction of HTB's hosted service or source -- the same way our
cryptopals17 adapter is our own implementation of the Cryptopals spec.

The twist vs. every other CBC entry in the dataset: the cipher is DES, so the block
size is 8 bytes (not AES's 16). The Vaudenay byte-recovery attack is identical apart
from the block-size loop bound.

Usage: python3 oracle_adapter.py <command> [args...]
  encrypt <plaintext> <key>   - PKCS#7-pad (block 8), DES-CBC encrypt; emits base64(IV||ct)
  decrypt <state> <key>       - DES-CBC decrypt; report ONLY padding validity
  serve   <key>               - persistent oracle: one base64 state per stdin line,
                                one JSON response per stdout line (use this for the
                                ~thousands of queries the attack needs)

Wire format: base64( IV[8] || ciphertext ).  DES key = SHA-256(<key>)[:8] (deterministic
so encrypt and the many serve decrypts agree). plaintext_b64 non-empty => padding VALID;
empty string => padding INVALID.
"""

import os
import sys
import json
import time
import base64
import hashlib
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad

BLOCK_SIZE = 8  # DES block size (vs 16 for AES)


def _derive_key(key):
    return hashlib.sha256(key.encode()).digest()[:8]  # DES is an 8-byte key


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
    """THE ORACLE: DES-CBC decrypt then manual PKCS#7 check. Returns base64(plaintext)
    on valid padding, "" on invalid padding / any failure."""
    try:
        combined = base64.b64decode(state)
    except Exception:
        return ""
    if len(combined) < 2 * BLOCK_SIZE or (len(combined) - BLOCK_SIZE) % BLOCK_SIZE != 0:
        return ""
    iv = combined[:BLOCK_SIZE]
    ct = combined[BLOCK_SIZE:]
    raw = DES.new(key, DES.MODE_CBC, iv).decrypt(ct)  # no automatic unpadding

    # Manual PKCS#7 padding check -- THIS IS THE ORACLE
    if len(raw) > 0:
        pad_byte = raw[-1]
        if 1 <= pad_byte <= BLOCK_SIZE and raw[-pad_byte:] == bytes([pad_byte]) * pad_byte:
            # Leak only one bit: fixed sentinel on VALID padding (no plaintext leak)
            return base64.b64encode(b"\x01").decode()
    return ""


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
        key = _derive_key(argv[3])

        iv = os.urandom(BLOCK_SIZE)
        ct = DES.new(key, DES.MODE_CBC, iv).encrypt(pad(plaintext, BLOCK_SIZE))
        packed = base64.b64encode(iv + ct).decode()
        print(json.dumps({"status": "success", "ciphertext": packed}))

    elif command == "decrypt":
        if len(argv) != 4:
            sys.stderr.write("Usage: decrypt <state> <key>\n")
            sys.exit(1)
        key = _derive_key(argv[3])
        start = time.time()
        result_b64 = _padding_oracle(argv[2], key)
        _log_oracle(bool(result_b64), (time.time() - start) * 1000.0)
        print(json.dumps({"status": "success", "plaintext_b64": result_b64}))

    elif command == "serve":
        if len(argv) != 3:
            sys.stderr.write("Usage: serve <key>\n")
            sys.exit(1)
        key = _derive_key(argv[2])
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
