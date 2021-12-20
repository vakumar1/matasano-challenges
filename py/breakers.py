import conversions as cnv

char_freqs = {
    'a': 0.08167,
    'b': 0.01492, 
    'c': 0.02782, 
    'd': 0.04253, 
    'e': 0.12702, 
    'f': 0.02228, 
    'g': 0.02015, 
    'h': 0.06094, 
    'i': 0.06966, 
    'j': 0.00153, 
    'k': 0.00772, 
    'l': 0.04025, 
    'm': 0.02406, 
    'n': 0.06749,
    'o': 0.07507,
    'p': 0.01929,
    'q': 0.00095,
    'r': 0.05987,
    's': 0.06327,
    't': 0.09056,
    'u': 0.02758,
    'v': 0.00978,
    'w': 0.02360,
    'x': 0.00150,
    'y': 0.01974,
    'z': 0.00074,
    ' ': 0.15
}

def sb_xor_encrypt(x, k):
    # encrypt PT X (hex string) with single byte key K (hex string)
    x_len = len(x) + (len(x) % 2)
    k_ext = cnv.extend(k, 2, x_len)
    y = cnv.base_to_int(x, 16) ^ cnv.base_to_int(k_ext, 16)
    return cnv.int_to_base(y, 16)

def sb_xor_decrypt(y, k):
    # decrypt CT Y (hex string) with single byte key K (hex string)
    y_len = len(y) + (len(y) % 2)
    k_ext = cnv.extend(k, 2, y_len)
    x = cnv.base_to_int(y, 16) ^ cnv.base_to_int(k_ext, 16)
    return cnv.int_to_base(x, 16)

def sb_xor_break_enc(y):
    # return best single byte key of CT Y (hex_string)
    best_prob = 0.0
    best_key = "0"
    for i in range(16 ** 2):
        k = cnv.int_to_base(i, 16)
        x = sb_xor_decrypt(y, k)
        prob = str_prob(x)
        if prob > best_prob:
            best_prob = prob
            best_key = k
    return best_key

def str_prob(x):
    # return the probability of PT X (hex string)
    eng_str = cnv.hex_to_ascii(x)
    score = 0.0
    for c in eng_str:
        try:
            score += char_freqs[c.lower()]
        except KeyError:
            score += 0
    if len(eng_str) == 0:
        return score
    else:
        return score / len(eng_str)

def rk_xor_encrypt(x, k):
    # encrypt PT X (hex string) with repeating key K (hex string)
    x_len = len(x) + (len(x) % 2)
    k_len = len(k) + (len(k) % 2)
    k_ext = cnv.extend(k, k_len, x_len)
    y = cnv.base_to_int(x, 16) ^ cnv.base_to_int(k_ext, 16)
    return cnv.int_to_base(y, 16)

def rk_xor_decrypt(y, k):
    # decrypt CT Y (hex string) with repeating key K (hex string)
    y_len = len(y) + (len(y) % 2)
    k_len = len(k) + (len(k) % 2)
    k_ext = cnv.extend(k, k_len, y_len)
    x = cnv.base_to_int(y, 16) ^ cnv.base_to_int(k_ext, 16)
    return cnv.int_to_base(x, 16)

def rk_xor_break(y):
    # return the best repeating key
    # split y into key_size blocks
    key_size = get_key_size(y, 2, 40, 10)
    block_strs = ["" for _ in range(key_size)]
    for i in range(0, len(y), 2):
        block_strs[(i // 2) % key_size] += y[i:i + 2]

    # for each hex block, find the best single byte key and append to key
    key = ""
    for block in block_strs:
        block_key = sb_xor_break_enc(block)
        if len(block_key) % 2 != 0:
            block_key = "0" + block_key
        key += block_key
    return key

def get_key_size(y, start, end, num_blocks):
    # return the best key_size for CT Y (hex string)
    # start: min key size
    # end: max key size
    # num blocks: how many blocks of CT Y to compare
    best_dist = float("inf")
    best_size = 0
    end = min(end, int(len(y) / (2 * num_blocks) - 1))
    for size in range(start, end):
        # split Y into blocks
        blocks = []
        for i in range(num_blocks):
            block = y[i * (size * 2):(i + 1) * (size * 2)]
            blocks.append(block)

        # get total hamming distance for all blocks
        dist = 0.0
        for i in range(num_blocks):
            for j in range(i):
                dist += hamming_dist(blocks[i], blocks[j])

        # update best key size using normalized distance
        norm_dist = dist / size
        if norm_dist < best_dist:
            best_dist = norm_dist
            best_size = size
    return best_size

def hamming_dist(s, t):
    # return hamming distance between S and T (hex strings)
    str_xor = cnv.base_to_int(s, 16) ^ cnv.base_to_int(t, 16)
    bit_diff = cnv.int_to_base(str_xor, 2)
    dist = 0
    for c in bit_diff:
        if c != "0":
            dist += 1
    return dist
