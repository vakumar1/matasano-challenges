import library.utilities as utils

############
# SHA1 MAC #
############

def sha1(inp):

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    ml = len(inp) * 8
    if ml % 512 == 448:
        padding_len = 448
    elif ml % 512 < 448:
        padding_len = 448 - (ml % 512)
    else:
        padding_len = 448 + (512 - (ml % 512))
    assert padding_len % 8 == 0 and padding_len > 0
    padding = bytearray(utils.NULL_BYTE * (padding_len // 8))
    padding[0] = 0x80
    inp += padding
    inp += utils.int_to_bytes(ml, 8)

    chunk_size = 64
    chunks = [inp[i:i + chunk_size] for i in range(0, len(inp), chunk_size)]
    for chunk in chunks:
        word_size = 4
        words = [chunk[i:i + word_size] for i in range(0, chunk_size, word_size)]
        for i in range(16, 80):
            new_word = utils.bytes_xor(words[i - 3], utils.bytes_xor(words[i - 8], utils.bytes_xor(words[i - 14], words[i - 16])))
            new_word = utils.bytes_leftrotate(new_word, 1)
            words.append(new_word)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        for i in range(80):
            if i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            tmp = utils.bytes_leftrotate(utils.int_to_bytes(a, 4), 5)
            tmp = (utils.bytes_to_int(tmp) + f + e + k + utils.bytes_to_int(words[i])) % (1 << 32)
            e = d
            d = c
            c = utils.bytes_to_int(utils.bytes_leftrotate(utils.int_to_bytes(b, 4), 30))
            b = a
            a = tmp
        h0 = (h0 + a) % (1 << 32)
        h1 = (h1 + b) % (1 << 32)
        h2 = (h2 + c) % (1 << 32)
        h3 = (h3 + d) % (1 << 32)
        h4 = (h4 + e) % (1 << 32)

    hh = utils.int_to_bytes(h0, 4) + utils.int_to_bytes(h1, 4) + utils.int_to_bytes(h2, 4) + utils.int_to_bytes(h3, 4) + utils.int_to_bytes(h4, 4)
    return hh


def sha1_mac_gen(key, inp):
    return sha1(key + inp)

def sha1_mac_verify(key, inp, mac):
    return sha1(key + inp) == mac
