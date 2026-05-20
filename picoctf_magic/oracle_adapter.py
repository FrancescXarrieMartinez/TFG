#!/usr/bin/env python3
"""
Oracle adapter for picoCTF 2018 "Magic Padding Oracle" -- VULNERABLE

CBC padding oracle CTF challenge. The original server (Python 2) decrypts a
hex-encoded IV||ciphertext, checks PKCS#7 padding with isvalidpad(), and reveals
whether the padding is valid (it prints "invalid padding" on failure). This
adapter wraps that exact logic behind the standard encrypt/decrypt CLI + JSON
shape used by the other dataset entries.

Usage: python3 oracle_adapter.py <command> [args...]
  encrypt <plaintext> <key>   - PKCS7-pad, AES-128-CBC encrypt; emits hex(iv||ct)
  decrypt <ciphertext> <key>  - AES-128-CBC decrypt; report ONLY padding validity

Wire format: hex(iv_bytes || raw_ct)  (first 32 hex chars = IV), matching the
picoCTF server's input format.
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


def _isvalidpad(s):
    # picoCTF server: isvalidpad(s) == (ord(s[-1])*s[-1:] == s[-ord(s[-1]):])
    # i.e. last byte n means the trailing n bytes must all equal n (PKCS#7).
    n = s[-1]
    return n != 0 and s[-n:] == bytes([n]) * n


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
        # Wire format: hex(iv || ct), matching the picoCTF server input
        print(json.dumps({"status": "success", "ciphertext": (iv + ct).hex()}))

    elif command == "decrypt":
        if len(argv) != 4:
            sys.stderr.write("Usage: decrypt <ciphertext> <key>\n")
            sys.exit(1)
        ciphertext = argv[2]
        key = argv[3].encode()

        start = time.time()
        combined = bytes.fromhex(ciphertext)
        iv = combined[:BLOCK_SIZE]
        ct = combined[BLOCK_SIZE:]
        raw = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)  # no automatic unpadding

        # THE ORACLE: picoCTF isvalidpad. Invalid padding => "invalid padding" => empty.
        result_b64 = ""
        if len(raw) > 0 and _isvalidpad(raw):
            n = raw[-1]
            plaintext = raw[:-n]
            # Non-empty sentinel when plaintext is empty (all-padding block)
            result_b64 = base64.b64encode(plaintext if plaintext else b"\x00").decode()

        _log_oracle(bool(result_b64), (time.time() - start) * 1000.0)
        print(json.dumps({"status": "success", "plaintext_b64": result_b64}))

    else:
        sys.stderr.write("Unknown command: %s\n" % command)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
