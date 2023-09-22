import library.utilities as utils

import secrets
import hashlib

def mod_exp(base, pow, mod):
    res = 1
    while pow > 0:
        if pow % 2 == 1:
            res = (res * base) % mod
        base = (base * base) % mod
        pow = pow // 2
    return res

def diffie_hellman_gen_keys(g, p):
    a = secrets.randbelow(p)
    b = secrets.randbelow(p)
    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)
    return (A, B, a, b)

def diffie_hellman_gen_secret(g, p, a, B):
    s = mod_exp(B, a, p)
    s_bytes = utils.int_to_bytes(s)
    hash = hashlib.sha256()
    hash.update(s_bytes)
    hash_bytes = hash.digest()
    assert(len(hash_bytes) == 32)
    encr_key = hash_bytes[:16]
    mac_key = hash_bytes[16:]
    return encr_key, mac_key
