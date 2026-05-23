BLOCK_SIZE = 16

def single_block_attack(block, oracle):
    zeroing_iv = [0] * BLOCK_SIZE

    for pad_val in range(1, BLOCK_SIZE + 1):
        padding_iv = [pad_val ^ b for b in zeroing_iv]

        for candidate in range(256):
            padding_iv[-pad_val] = candidate
            iv = bytes(padding_iv)
            if oracle(iv, block):
                if pad_val == 1:
                    padding_iv[-2] ^= 1
                    iv = bytes(padding_iv)
                    if not oracle(iv, block):
                        continue
                break
        else:
            raise Exception("no valid padding byte found")

        zeroing_iv[-pad_val] = candidate ^ pad_val

    return zeroing_iv

def full_attack(iv, ct, oracle):
    msg = iv + ct
    blocks = [msg[i:i+BLOCK_SIZE] for i in range(0, len(msg), BLOCK_SIZE)]
    result = b''

    prev = blocks[0]
    for block in blocks[1:]:
        dec = single_block_attack(block, oracle)
        pt = bytes(a ^ b for a, b in zip(prev, dec))
        result += pt
        prev = block

    return result
