#!/usr/bin/env python3
"""
Oracle adapter for Cryptopals Set 3, Challenge 17 (CBC padding oracle) -- VULNERABLE

Minimal CLI wrapper around the challenge AES-128-CBC encrypt / padding-check logic.
Mirrors the PrestaShop oracle adapter JSON shape.

Usage: python3 oracle_adapter.py <command> [args...]
  encrypt <plaintext> <key>   - PKCS7-pad, AES-128-CBC encrypt; random IV prepended
  decrypt <ciphertext> <key>  - AES-128-CBC decrypt; report ONLY padding validity
"""

import os
import sys
import json
import time
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

BLOCK_SIZE = 16


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
        key = argv[3].encode()

        iv = os.urandom(BLOCK_SIZE)
        ct = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext, BLOCK_SIZE))

        # Wire format: base64(iv || ct)
        packed = base64.b64encode(iv + ct).decode()
        print(json.dumps({"status": "success", "ciphertext": packed}))

    elif command == "decrypt":
        if len(argv) != 4:
            sys.stderr.write("Usage: decrypt <ciphertext> <key>\n")
            sys.exit(1)
        ciphertext = argv[2]
        key = argv[3].encode()

        start = time.time()
        combined = base64.b64decode(ciphertext)
        iv = combined[:BLOCK_SIZE]
        ct = combined[BLOCK_SIZE:]

        raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)  # no automatic unpadding

        # Manual PKCS7 padding check -- THIS IS THE ORACLE
        result_b64 = ""
        if len(raw) > 0:
            pad_byte = raw[-1]
            if 1 <= pad_byte <= BLOCK_SIZE and raw[-pad_byte:] == bytes([pad_byte]) * pad_byte:
                plaintext = raw[:-pad_byte]
                # Non-empty sentinel when plaintext is empty (all-padding block)
                result_b64 = base64.b64encode(plaintext if plaintext else b"\x00").decode()

        _log_oracle(bool(result_b64), (time.time() - start) * 1000.0)
        print(json.dumps({"status": "success", "plaintext_b64": result_b64}))

    else:
        sys.stderr.write("Unknown command: %s\n" % command)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
