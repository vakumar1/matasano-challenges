import library.utilities as utils

###################
# SINGLY BYTE XOR #
###################

def sb_xor_encrypt(x, k):
    # encrypt PT X with single byte key K
    k_ext = utils.byte_extend(k, 1, len(x))
    y = utils.bytes_xor(x, k_ext)
    return y

def sb_xor_decrypt(y, k):
    # decrypt CT Y with single byte key K
    k_ext = utils.byte_extend(k, 1, len(y))
    x = utils.bytes_xor(y, k_ext)
    return x

def sb_xor_break_enc(y):
    # return best single byte key of CT Y
    best_prob = 0.0
    best_key = utils.int_to_bytes(0, 1)
    for i in range(16 ** 2):
        k = utils.int_to_bytes(i, 1)
        x = sb_xor_decrypt(y, k)
        prob = utils.str_prob(x)
        if prob > best_prob:
            best_prob = prob
            best_key = k
    return best_key

#####################
# REPEATING KEY XOR #
#####################

def rk_xor_encrypt(x, k):
    # encrypt PT X with repeating key K
    k_ext = utils.byte_extend(k, len(k), len(x))
    y = utils.bytes_xor(x, k_ext) 
    return y

def rk_xor_decrypt(y, k):
    # decrypt CT Y with repeating key K
    k_ext = utils.byte_extend(k, len(k), len(y))
    x = utils.bytes_xor(y, k_ext)
    return x

def rk_xor_break(y, key_size=0):
    # return the best repeating key with KEY_SIZE
    # if no key size provided, use estimate from hamming dist
    if key_size == 0:
        key_size = get_key_size(y, 2, 40, 10)
    
    # split y into key_size blocks
    blocks = [bytearray() for _ in range(key_size)]
    for i in range(len(y)):
        blocks[i % key_size].append(y[i])

    # for each hex block, find the best single byte key and append to key
    key = bytearray()
    for block in blocks:
        block_key = sb_xor_break_enc(block)
        key.append(int.from_bytes(block_key, "big"))
    return key

def get_key_size(y, start, end, num_blocks):
    # return the best key_size for CT Y (hex string)
    # start: min key size
    # end: max key size
    # num blocks: how many blocks of CT Y to compare
    best_dist = float("inf")
    best_size = 0
    end = min(end, int(len(y) / num_blocks) - 1)
    for size in range(start, end):
        # split Y into blocks
        blocks = []
        for i in range(num_blocks):
            block = y[i * size:(i + 1) * size]
            blocks.append(block)

        # get total hamming distance for all blocks
        dist = 0.0
        for i in range(num_blocks):
            for j in range(i):
                dist += utils.hamming_dist(blocks[i], blocks[j])

        # update best key size using normalized distance
        norm_dist = dist / size
        if norm_dist < best_dist:
            best_dist = norm_dist
            best_size = size
    return best_size