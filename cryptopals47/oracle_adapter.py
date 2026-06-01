#!/usr/bin/env python3
"""
Oracle adapter for Cryptopals Set 6, Challenge 47
(Bleichenbacher PKCS#1 v1.5 RSA padding oracle, simple case) -- VULNERABLE

Minimal CLI wrapper. Mirrors the PrestaShop / Cryptopals-17 oracle JSON shape.

Usage: python3 oracle_adapter.py <command> [args...]
  encrypt <plaintext> <key>   - PKCS#1 v1.5 pad, RSA encrypt; emits packed (n,e,c)
  decrypt <ciphertext> <key>  - RSA decrypt; report ONLY whether padding starts 00 02
  serve <key>                 - persistent oracle: one base64 ciphertext per stdin
                                line, one JSON response per stdout line. Use this
                                for the ~10^4-10^5 queries Bleichenbacher needs;
                                a fresh process per query is far too slow.

The RSA keypair is derived deterministically from <key> so that encrypt and the
many decrypt (oracle) calls share the same modulus across separate processes.
The public modulus/exponent travel inside the ciphertext (they are public); the
private exponent never leaves this adapter.
"""

import os
import sys
import json
import time
import base64
import hashlib

KEY_BITS = 256
E = 65537


def _det_randfunc(seed_bytes):
    """Deterministic byte stream from a seed (reproducible RSA keygen across processes)."""
    state = {"buf": bytearray(), "ctr": 0}

    def randfunc(n):
        while len(state["buf"]) < n:
            state["buf"] += hashlib.sha256(seed_bytes + state["ctr"].to_bytes(8, "big")).digest()
            state["ctr"] += 1
        out = bytes(state["buf"][:n])
        del state["buf"][:n]
        return out

    return randfunc


def _gen_keypair(seed):
    # Imported lazily so the cached-key decrypt fast-path stays pure-stdlib (faster per call).
    from Crypto.Util.number import getPrime, inverse, GCD
    rf = _det_randfunc(seed.encode())
    while True:
        p = getPrime(KEY_BITS // 2, rf)
        q = getPrime(KEY_BITS // 2, rf)
        if p == q:
            continue
        phi = (p - 1) * (q - 1)
        if GCD(E, phi) == 1:
            return p * q, E, inverse(E, phi)


def _load_keypair(seed):
    """Deterministic keypair from seed, cached in /tmp to avoid regen on every call."""
    tag = hashlib.sha256(("%d:%d:%s" % (KEY_BITS, E, seed)).encode()).hexdigest()[:16]
    cache = os.path.join("/tmp", "co47_key_%s.json" % tag)
    try:
        with open(cache) as f:
            kp = json.load(f)
        return int(kp["n"]), int(kp["e"]), int(kp["d"])
    except (OSError, ValueError, KeyError):
        n, e, d = _gen_keypair(seed)
        try:
            with open(cache, "w") as f:
                json.dump({"n": str(n), "e": str(e), "d": str(d)}, f)
        except OSError:
            pass
        return n, e, d


def _log_oracle(valid, elapsed_ms):
    """Append one JSON line per oracle query when ORACLE_LOG is set (reward telemetry)."""
    path = os.environ.get("ORACLE_LOG")
    if not path:
        return
    try:
        with open(path, "a") as f:
            f.write(json.dumps({"valid": bool(valid), "elapsed_ms": elapsed_ms}) + "\n")
    except OSError:
        pass


def _pack(n, e, c):
    blob = json.dumps({"n": format(n, "x"), "e": format(e, "x"), "c": format(c, "x")})
    return base64.b64encode(blob.encode()).decode()


def _unpack(ciphertext):
    blob = json.loads(base64.b64decode(ciphertext).decode())
    return int(blob["n"], 16), int(blob["e"], 16), int(blob["c"], 16)


def _is_conformant(c, n, d, k):
    """THE ORACLE: PKCS#1 v1.5 conformance, simple case = first two bytes 00 02."""
    em = pow(c, d, n).to_bytes(k, "big")
    return em[0] == 0x00 and em[1] == 0x02


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
        message = argv[2].encode()
        seed = argv[3]
        n, e, d = _load_keypair(seed)
        k = (n.bit_length() + 7) // 8

        # PKCS#1 v1.5 type 2: 00 02 || PS (>=8 nonzero random) || 00 || M
        ps_len = k - 3 - len(message)
        if ps_len < 8:
            sys.stderr.write("message too long for modulus\n")
            sys.exit(1)
        ps = bytearray()
        while len(ps) < ps_len:
            b = os.urandom(1)
            if b != b"\x00":
                ps += b
        em = b"\x00\x02" + bytes(ps) + b"\x00" + message
        c = pow(int.from_bytes(em, "big"), e, n)
        print(json.dumps({"status": "success", "ciphertext": _pack(n, e, c)}))

    elif command == "decrypt":
        if len(argv) != 4:
            sys.stderr.write("Usage: decrypt <ciphertext> <key>\n")
            sys.exit(1)
        ciphertext = argv[2]
        seed = argv[3]
        start = time.time()
        n, e, d = _load_keypair(seed)
        k = (n.bit_length() + 7) // 8
        _, _, c = _unpack(ciphertext)

        valid = _is_conformant(c, n, d, k)
        # Non-empty sentinel when padding is VALID, empty string when INVALID
        result_b64 = base64.b64encode(b"\x01").decode() if valid else ""

        _log_oracle(valid, (time.time() - start) * 1000.0)
        print(json.dumps({"status": "success", "plaintext_b64": result_b64}))

    elif command == "serve":
        # Persistent oracle: key loaded ONCE, then answer base64-ciphertext queries
        # line-by-line on stdin with one JSON response per line on stdout. Same
        # padding check and same plaintext_b64 convention as the one-shot decrypt.
        if len(argv) != 3:
            sys.stderr.write("Usage: serve <key>\n")
            sys.exit(1)
        seed = argv[2]
        n, e, d = _load_keypair(seed)
        k = (n.bit_length() + 7) // 8
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            start = time.time()
            try:
                _, _, c = _unpack(line)
                valid = _is_conformant(c, n, d, k)
            except Exception:
                valid = False
            result_b64 = base64.b64encode(b"\x01").decode() if valid else ""
            _log_oracle(valid, (time.time() - start) * 1000.0)
            sys.stdout.write(json.dumps({"status": "success", "plaintext_b64": result_b64}) + "\n")
            sys.stdout.flush()

    else:
        sys.stderr.write("Unknown command: %s\n" % command)
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv)
