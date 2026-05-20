#!/usr/bin/env python3
"""
Padding oracle exploit for the Cryptopals 17 CBC oracle adapter.
Invoked as: python3 exploit.py <oracle_path> <key> <ciphertext>
Recovers plaintext WITHOUT the AES key, using only padding validity.
"""
import sys
import json
import base64
import subprocess

BLOCK_SIZE = 16


def make_oracle(oracle_path, key):
    def oracle(iv_bytes, block):
        packed = base64.b64encode(bytes(iv_bytes) + bytes(block)).decode()
        r = subprocess.run(
            [sys.executable, oracle_path, "decrypt", packed, key],
            capture_output=True, text=True,
        )
        try:
            resp = json.loads(r.stdout)
        except json.JSONDecodeError:
            return False
        return bool(resp.get("plaintext_b64", ""))  # non-empty => padding VALID
    return oracle


def single_block_attack(block, oracle):
    zeroing_iv = [0] * BLOCK_SIZE
    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]
        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            if oracle(padding_iv, block):
                if pad_val == 1:
                    # Disambiguate real 0x01 padding from accidental longer padding
                    padding_iv[-2] ^= 1
                    if not oracle(padding_iv, block):
                        padding_iv[-2] ^= 1
                        continue
                    padding_iv[-2] ^= 1
                break
        else:
            raise Exception("no valid padding byte found at position %d" % pad_val)
        zeroing_iv[-pad_val] = candidate ^ pad_val
    return zeroing_iv


def full_attack(iv, ct, oracle):
    blocks = [iv] + [ct[i:i + BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    recovered, prev = b"", blocks[0]
    for block in blocks[1:]:
        zeroing_iv = single_block_attack(block, oracle)
        recovered += bytes(a ^ b for a, b in zip(prev, zeroing_iv))
        prev = block
    return recovered


def pkcs7_unpad(data):
    if not data:
        return data
    pad_byte = data[-1]
    if 1 <= pad_byte <= BLOCK_SIZE and data[-pad_byte:] == bytes([pad_byte]) * pad_byte:
        return data[:-pad_byte]
    return data


def main():
    oracle_path, key, ciphertext = sys.argv[1], sys.argv[2], sys.argv[3]
    combined = base64.b64decode(ciphertext)
    iv, ct = combined[:BLOCK_SIZE], combined[BLOCK_SIZE:]
    recovered = full_attack(iv, ct, make_oracle(oracle_path, key))
    sys.stdout.write(pkcs7_unpad(recovered).decode("utf-8", errors="replace"))


if __name__ == "__main__":
    main()
