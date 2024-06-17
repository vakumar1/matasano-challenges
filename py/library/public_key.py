import library.aes as aes
import library.mac as mac
import library.utilities as utils

import secrets
import hashlib, hmac
from Crypto.Util import number
import math

from decimal import Decimal, getcontext

###############################
# DIFFIE-HELLMAN KEY EXCHANGE #
###############################

DEF_P = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
DEF_G = 2

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
    A = mod_exp(g, a, p)
    return a, A

def sha256_keymac_hash_fn(b):
    hash = hashlib.sha256()
    hash.update(b)
    hash_bytes = hash.digest()
    assert(len(hash_bytes) == 2 * aes.BLOCK_SIZE)
    encr_key = hash_bytes[:aes.BLOCK_SIZE]
    mac_key = hash_bytes[aes.BLOCK_SIZE:]
    return encr_key, mac_key

def sha1_keymac_hash_fn(b):
    hash_bytes = mac.sha1(b)
    encr_key = hash_bytes[:aes.BLOCK_SIZE]
    mac_key = bytearray()
    return encr_key, mac_key

def diffie_hellman_gen_secret(g, p, a, B, keymac_hash_fn):
    s = mod_exp(B, a, p)
    s_bytes = utils.int_to_bytes(s)
    return keymac_hash_fn(s_bytes)

##################################
# DH MITM PARAM INJECTION ATTACK #
##################################

class DHSender:
    def __init__(self):
        self.p, self.g = DEF_P, DEF_G
        self.a, self.A = diffie_hellman_gen_keys(self.g, self.p)
    
    def init_msg(self):
        # send parameters + public key
        return (self.p, self.g, self.A)
    
    def handle_init_msg(self, B):
        # store public key
        self.B = B
    
    def data_msg(self, data):
        # send encrypted data + iv
        self.data = data
        encr_key, _ = diffie_hellman_gen_secret(self.g, self.p, self.a, self.B, sha1_keymac_hash_fn)
        sender_iv = secrets.token_bytes(aes.BLOCK_SIZE)
        return aes.aes_cbc_encrypt(data, encr_key, sender_iv) + sender_iv
    
    def verify_data_msg(self, received):
        # receive encrypted data (under their iv) and return boolean for whether data is correct
        encr_key, _ = diffie_hellman_gen_secret(self.g, self.p, self.a, self.B, sha1_keymac_hash_fn)
        encr_data = received[:-aes.BLOCK_SIZE]
        receiver_iv = received[-aes.BLOCK_SIZE:]
        data = utils.remove_pkcs7_pad(aes.aes_cbc_decrypt(encr_data, encr_key, receiver_iv), aes.BLOCK_SIZE)
        return data == self.data

    
class DHReceiver:
    def init_msg(self, p, g, A):
        # receive parameters/public key and return my public key
        self.p, self.g, self.A = p, g, A
        self.b, self.B = diffie_hellman_gen_keys(self.g, self.p)
        return self.B

    def data_msg(self, received):
        # receive encrypted data/iv, decrypt data and return encrypted data (under my iv)
        encr_key, _ = diffie_hellman_gen_secret(self.g, self.p, self.b, self.A, sha1_keymac_hash_fn)
        encr_data = received[:-aes.BLOCK_SIZE]
        sender_iv = received[-aes.BLOCK_SIZE:]
        data = utils.remove_pkcs7_pad(aes.aes_cbc_decrypt(encr_data, encr_key, sender_iv), aes.BLOCK_SIZE)
        self.data = data
        receiver_iv = secrets.token_bytes(aes.BLOCK_SIZE)
        return aes.aes_cbc_encrypt(data, encr_key, receiver_iv) + receiver_iv

class DHMITM:
    def inject_init_msg_sender(self, p, g, A):
        self.p = p
        return p, g, p
    
    def inject_init_msg_receiver(self, B):
        return self.p
    
    def decrypt_intercepted_msg(self, received):
        s = 0
        s_bytes = utils.int_to_bytes(s)
        encr_key, _ = sha1_keymac_hash_fn(s_bytes)

        encr_data = received[:-aes.BLOCK_SIZE]
        sender_iv = received[-aes.BLOCK_SIZE:]
        data = utils.remove_pkcs7_pad(aes.aes_cbc_decrypt(encr_data, encr_key, sender_iv), aes.BLOCK_SIZE)
        return data
    
class DHSenderNegotiated(DHSender):
    def __init__(self):
        self.p, self.g = DEF_P, DEF_G

    def init_msg(self):
        return (self.p, self.g)
    
    def init_msg2(self, ack):
        if ack:
            self.a, self.A = diffie_hellman_gen_keys(self.g, self.p)
            return self.A
        return None
    

class DHReceiverNegotiated(DHReceiver):
    def init_msg(self, p, g):
        # default to always approve parameters
        self.p, self.g = p, g
        return True
    
    def init_msg2(self, A):
        self.A = A
        self.b, self.B = diffie_hellman_gen_keys(self.g, self.p)
        return self.B
    
class DHMITM_g:
    def __init__(self, fn):
        # parameterize attack by fn (computes injected g, injected A, and s as a function of p)
        self.fn = fn

    def inject_init_msg_sender(self, p, g):
        self.p = p
        self.g, self.A, self.s = self.fn(p)
        return p, self.g
    
    def inject_init_msg2_sender(self, A):
        return self.A
    
    def decrypt_intercepted_msg(self, received):
        s = self.s
        s_bytes = utils.int_to_bytes(s)
        encr_key, _ = sha1_keymac_hash_fn(s_bytes)

        encr_data = received[:-aes.BLOCK_SIZE]
        sender_iv = received[-aes.BLOCK_SIZE:]
        data = utils.remove_pkcs7_pad(aes.aes_cbc_decrypt(encr_data, encr_key, sender_iv), aes.BLOCK_SIZE)
        return data
    
#######
# SRP #
#######

class SRPServer:
    def __init__(self):
        self.p, self.g, self.k = DEF_P, DEF_G, 3
        self.data = {}
    
    def send_params(self):
        return self.p, self.g, self.k
    
    def recv_new_email(self, email, password):
        salt = secrets.token_bytes(16)
        hash = hashlib.sha256()
        hash.update(salt + password)
        xH = hash.digest()
        x = utils.bytes_to_int(xH)
        v = mod_exp(self.g, x, self.p)
        self.data[email] = {
            "salt": salt,
            "v": v,
        }

    def recv_auth_init(self, email, A):
        salt = self.data[email]["salt"]
        v = self.data[email]["v"]
        b = secrets.randbelow(self.p)
        B = (self.k * v + mod_exp(self.g, b, self.p)) % self.p

        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(A + B))
        uH = hash.digest()
        u = utils.bytes_to_int(uH)
        S = mod_exp(A * mod_exp(v, u, self.p), b, self.p)
        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(S))
        K = hash.digest()
        self.data[email]["K"] = K

        return salt, B
    
    def recv_auth_req(self, email, hash):
        K = self.data[email]["K"]
        salt = self.data[email]["salt"]
        mac = hmac.HMAC(K, digestmod=hashlib.sha256)
        mac.update(salt)
        return mac.digest() == hash


class SRPClient:
    def __init__(self, email, password):
        self.email, self.password = email, password

    def recv_params(self, p, g, k):
        self.p, self.g, self.k = p, g, k

    def send_new_email(self):
        return self.email, self.password
    
    def send_auth_init(self):
        self.a = secrets.randbelow(self.p)
        self.A = mod_exp(self.g, self.a, self.p)
        return self.email, self.A
    
    def handle_auth_init(self, salt, B):
        self.salt = salt
        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(self.A + B))
        uH = hash.digest()
        u = utils.bytes_to_int(uH)

        hash = hashlib.sha256()
        hash.update(salt + self.password)
        xH = hash.digest()
        x = utils.bytes_to_int(xH)

        S = mod_exp(B - self.k * mod_exp(self.g, x, self.p), self.a + u * x, self.p)
        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(S))
        self.K = hash.digest()

    def send_auth_req(self):
        mac = hmac.HMAC(self.K, digestmod=hashlib.sha256)
        mac.update(self.salt)
        return self.email, mac.digest()


class MaliciousSRPClient:
    # malicious client needs to know params beforehand
    def __init__(self, p, g, k):
        self.p, self.g, self.k = p, g, k

    def send_auth_init(self, victim_email):
        self.email = victim_email
        return victim_email, 0
    
    def handle_auth_init(self, salt, B):
        self.salt = salt
        S = 0
        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(S))
        self.K = hash.digest()

    def send_auth_req(self):
        mac = hmac.HMAC(self.K, digestmod=hashlib.sha256)
        mac.update(self.salt)
        return self.email, mac.digest()
    
############################
# DICTIONARY ATTACK ON SRP #
############################
class SimpleSRPServer:
    def __init__(self):
        self.p, self.g = DEF_P, DEF_G
        self.data = {}

    def send_params(self):
        return self.p, self.g

    def recv_new_email(self, email, password):
        salt = secrets.token_bytes(16)
        hash = hashlib.sha256()
        hash.update(salt + password)
        xH = hash.digest()
        x = utils.bytes_to_int(xH)
        v = mod_exp(self.g, x, self.p)
        self.data[email] = {
            "salt": salt,
            "v": v
        }

    def recv_auth_init(self, email, A):
        salt = self.data[email]["salt"]
        v = self.data[email]["v"]
        b = secrets.randbelow(self.p)
        u = utils.bytes_to_int(secrets.token_bytes(16))
        B = mod_exp(self.g, b, self.p)

        S = mod_exp(A * mod_exp(v, u, self.p), b, self.p)
        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(S))
        K = hash.digest()
        self.data[email]["K"] = K

        return salt, B, u
    
    def recv_auth_req(self, email, hash):
        K = self.data[email]["K"]
        salt = self.data[email]["salt"]
        mac = hmac.HMAC(K, digestmod=hashlib.sha256)
        mac.update(salt)
        return mac.digest() == hash

class MITMSimpleSRPServer:
    def __init__(self, p, g):
        self.p, self.g = p, g

    def recv_auth_init(self, email, A):
        self.salt = secrets.token_bytes(16)
        self.b = secrets.randbelow(self.p)
        self.u = utils.bytes_to_int(secrets.token_bytes(16))
        B = mod_exp(self.g, self.b, self.p)

        # store auth init data for MITM server
        self.A = A

        return self.salt, B, self.u

    # dictionary attack on client's hmac
    def recv_auth_req(self, email, hash):
        salt = self.salt
        A = self.A
        b = self.b
        u = self.u

        def password_valid(password):
            xhash = hashlib.sha256()
            xhash.update(salt + password)
            xH = xhash.digest()
            x = utils.bytes_to_int(xH)
            v = mod_exp(self.g, x, self.p)
            S = mod_exp(A * mod_exp(v, u, self.p), b, self.p)
            shash = hashlib.sha256()
            shash.update(utils.int_to_bytes(S))
            K = shash.digest()
            mac = hmac.HMAC(K, digestmod=hashlib.sha256)
            mac.update(salt)
            return mac.digest() == hash

        # assume password is 8 bytes long
        for i in range(8 ** 16):
            password = utils.int_to_bytes(i, 8)
            if password_valid(password):
                return password
        return bytearray()

    
class SimpleSRPClient:
    def __init__(self, email, password):
        self.email, self.password = email, password

    def recv_params(self, p, g):
        self.p, self.g = p, g

    def send_new_email(self):
        return self.email, self.password

    def send_auth_init(self):
        self.a = secrets.randbelow(self.p)
        self.A = mod_exp(self.g, self.a, self.p)
        return self.email, self.A

    def handle_auth_init(self, salt, B, u):
        self.salt = salt
        hash = hashlib.sha256()
        hash.update(salt + self.password)
        xH = hash.digest()
        x = utils.bytes_to_int(xH)
        S = mod_exp(B, self.a + u * x, self.p)
        hash = hashlib.sha256()
        hash.update(utils.int_to_bytes(S))
        self.K = hash.digest()
    
    def send_auth_req(self):
        mac = hmac.HMAC(self.K, digestmod=hashlib.sha256)
        mac.update(self.salt)
        return self.email, mac.digest()


#######
# RSA #
#######

def egcd(b, a):
    if a < b:
        b = b % a
    r0 = a
    r1 = b
    s0, t0 = 1, 0
    s1, t1 = 0, 1
    while True:
        q = r0 // r1
        new_r = r0 % r1
        new_s = s0 - q * s1
        new_t = t0 - q * t1
        r0, r1 = r1, new_r
        s0, s1 = s1, new_s
        t0, t1 = t1, new_t
        if new_r == 0:
            break
    if r0 != 1:
        raise ValueError("Trying to take modular inverse of noncoprime numbers.")
    return t0
    
def rsa_gen_params(factor_mod_bits=1024, e=3):
    p = number.getPrime(factor_mod_bits)
    while p % 3 != 2:
        p = number.getPrime(factor_mod_bits)
    q = number.getPrime(factor_mod_bits)
    while q % 3 != 2:
        q = number.getPrime(factor_mod_bits)
    N = p * q
    et = (p - 1) * (q - 1)
    d = (egcd(e, et)) % et
    return factor_mod_bits, (N, e), (N, d)

def rsa_encrypt(m, public_key):
    N, e = public_key
    return mod_exp(m, e, N)

def rsa_decrypt(c, private_key):
    N, d = private_key
    return mod_exp(c, d, N)

##################
# RSA CRT ATTACK #
##################

def break_rsa_crt(ciphers, public_keys):
    c0, c1, c2 = ciphers
    (N0, _), (N1, _), (N2, _) = public_keys
    M = N0 * N1 * N2
    M0 = N1 * N2
    M1 = N0 * N2
    M2 = N0 * N1
    Y0 = egcd(M0, N0)
    Y1 = egcd(M1, N1)
    Y2 = egcd(M2, N2)
    m_3 = c0 * (Y0 * M0) + c1 * (Y1 * M1) + c2 * (Y2 * M2)
    return m_3

###############################
# BREAK RSA DECRYPTION ORACLE #
###############################

class RSADecryptionOracle:

    def __init__(self):
        self.decrypted = set()
        self.rsa_bits, self.public_key, self.private_key = rsa_gen_params()

    def key(self):
        return self.public_key

    def decrypt(self, c):
        if c in self.decrypted:
            raise PermissionError("Duplicated ciphertext")
        self.decrypted.add(c)
        p = rsa_decrypt(c, self.private_key)
        return p

def break_rsa_oracle(c, oracle: RSADecryptionOracle):
    N, e = oracle.key()
    S = secrets.randbelow(N - 2) + 2
    c_ = (mod_exp(S, e, N) * c) % N
    p_ = oracle.decrypt(c_)
    p = (p_ * egcd(S, N)) % N
    return p

#######################
# RSA EVEN/ODD ORACLE #
#######################

def get_rsa_even_odd_oracle(priv_key):
    def oracle(c):
        N, d = priv_key
        m = rsa_decrypt(c, priv_key)
        return m % 2 == 0
    return oracle

def break_rsa_even_odd_oracle(oracle, rsa_bits, pub_key, c):
    rsa_bytes = rsa_bits // 8
    def float_to_ascii(sum):
        return utils.bytes_to_ascii(utils.int_to_bytes(int(sum), rsa_bytes * 2))

    N, e = pub_key
    getcontext().prec = 3000
    curr_sum = Decimal(0)
    for i in range(rsa_bits * 2 + 20):
        coef = 2 ** (i + 1)
        even = oracle((coef ** e) * c)
        if not even:
            curr_sum += Decimal(N) / Decimal(coef)
        if i % 10 == 0:
            print(i, float_to_ascii(curr_sum))
    return float_to_ascii(curr_sum)

######################
# PKCS1.5 MAC ATTACK #
######################

# ASN.1 DER encoding for sha256 hash digest
SHA_256_DER_ENC = bytes.fromhex("30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20")
SHA_256_HASH_BYTES = 32

def pkcs1_message_hash_pad(message, rsa_bits):
    # get sha256 hash of message
    rsa_bytes = rsa_bits // 8
    h = hashlib.sha256()
    h.update(message)
    message_hash = h.digest()
    assert len(message_hash) == SHA_256_HASH_BYTES
    ff_bytes = rsa_bytes - (2 + 1 + len(SHA_256_DER_ENC) + len(message_hash))
    assert ff_bytes >= 0

    # prepend padding to message hash
    padding = bytearray()
    padding += utils.NULL_BYTE
    padding += bytes.fromhex("01")
    padding += (ff_bytes * utils.ONE_BYTE)
    padding += utils.NULL_BYTE
    padding += SHA_256_DER_ENC
    padding += message_hash
    assert len(padding) == rsa_bytes
    return padding

def faulty_remove_pkcs1_message_hash_pad(padded_message):
    
    states = [
        "START",
        "FF_BYTES",
        "TAIL",
    ]
    state = "START"
    i = 0
    while i < len(padded_message):
        if state == "START":
            if padded_message[i:i + 1] == utils.NULL_BYTE and padded_message[i + 1:i + 2] == bytes.fromhex("01"):
                state = "FF_BYTES"
                i += 2
            else:
                state = "START"
                i += 1
        elif state == "FF_BYTES":
            if padded_message[i:i + 1] == utils.ONE_BYTE:
                state = "FF_BYTES"
                i += 1
            elif padded_message[i:i + 1] == utils.NULL_BYTE:
                state = "TAIL"
                i += 1
            else:
                state = "START"
                i += 1
        elif state == "TAIL":
            # only verify for sha256 hash
            der_bytes = padded_message[i:i + len(SHA_256_DER_ENC)]
            if der_bytes == SHA_256_DER_ENC:
                message_hash = padded_message[(i + len(SHA_256_DER_ENC)):(i + len(SHA_256_DER_ENC)) + SHA_256_HASH_BYTES]
                return message_hash
            else:
                state = "START"
                i += 1
    raise ValueError("Failed to parse pkcs1.5-padded message (or could not find OID for supported hash algo)")

def rsa_sign_sha256(message, rsa_bits, private_key):
    padded_message_hash = pkcs1_message_hash_pad(message, rsa_bits)
    signature = rsa_decrypt(utils.bytes_to_int(padded_message_hash), private_key)
    return signature

def verify_rsa_signature_sha256(message, signature, rsa_bits, public_key):
    rsa_bytes = rsa_bits // 8
    expected_padded_message_hash = utils.int_to_bytes(rsa_encrypt(signature, public_key), rsa_bytes)
    expected_message_hash = faulty_remove_pkcs1_message_hash_pad(expected_padded_message_hash)
    h = hashlib.sha256()
    h.update(message)
    actual_message_hash = h.digest()
    return expected_message_hash == actual_message_hash

def bounded_cube_root(low_bound, high_bound):
    L = 0
    M = 0
    R = low_bound
    while L < R - 1:
        M = (L + R) // 2
        cube_M = M * M * M
        if cube_M >= low_bound and cube_M <= high_bound:
            return M
        elif cube_M < low_bound:
            L = M
        else:
            R = M
    return None

    
def create_forged_pkcs1_signature(message, rsa_bits):
    # get sha256 hash of message
    h = hashlib.sha256()
    h.update(message)
    message_hash = h.digest()

    cube_signature = bytearray()
    cube_signature += utils.NULL_BYTE
    cube_signature += bytes.fromhex("01")
    cube_signature += (0 * utils.ONE_BYTE) # prepend 0 FF bytes
    cube_signature += utils.NULL_BYTE
    cube_signature += SHA_256_DER_ENC
    cube_signature += message_hash

    rsa_bytes = rsa_bits // 8
    remaining_bytes = rsa_bytes - len(cube_signature) # 128 - 54 = 74 bytes remaining
    low_cube_signature = cube_signature + remaining_bytes * utils.NULL_BYTE
    high_cube_signature = cube_signature + remaining_bytes * utils.ONE_BYTE
    signature = bounded_cube_root(utils.bytes_to_int(low_cube_signature), utils.bytes_to_int(high_cube_signature))
    if not signature:
        raise Exception("Failed to find value whose cube would produce an acceptable forged signature.")
    return signature

#######
# DSA #
#######

DSA_P = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
DSA_G = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
DSA_Q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b


def dsa_gen_keys(g, p, q):
    priv_key = 1 + secrets.randbelow(q - 1)
    pub_key = mod_exp(g, priv_key, p)
    return (priv_key, pub_key)

def dsa_sign_message(m, priv_key, g, p, q):
    k = 1 + secrets.randbelow(q - 1)
    r = mod_exp(g, k, p) % q
    k_inv = egcd(k, q)
    h = hashlib.sha1()
    h.update(m)
    m_hash = h.digest()
    m_hash_num = utils.bytes_to_int(m_hash)
    s = ((m_hash_num + priv_key * r) * k_inv) % q
    return (r, s)

def dsa_verify_message(m, sig, pub_key, g, p, q):
    (r, s) = sig
    w = egcd(s, q)
    h = hashlib.sha1()
    h.update(m)
    m_hash = h.digest()
    m_hash_num = utils.bytes_to_int(m_hash)
    u1 = (m_hash_num * w) % q
    u2 = (r * w) % q
    v = (mod_exp(g, u1, p) * mod_exp(pub_key, u2, p) % p) % q
    return v == r

##############################
# DSA K PRIVATE KEY RECOVERY #
##############################

def dsa_recover_priv_key_from_k(m_hash_num, r_inv, s, k, g, p, q):
    return ((s * k - m_hash_num) * r_inv) % q

def dsa_recover_priv_key_brute_force_k(m_hash_num, sig, pub_key, g, p, q):
    (r, s) = sig
    r_inv = egcd(r, q)
    for k in range(1 << 16):
        priv_key_cand = dsa_recover_priv_key_from_k(m_hash_num, r_inv, s, k, g, p, q)
        if mod_exp(g, priv_key_cand, p) == pub_key:
            return priv_key_cand
        
def desa_recover_priv_key_repeated_k(sigs, public_key, g, p, q):
    for (i, sig) in enumerate(sigs):
        for j in range(i):
            (r1, s1) = sigs[i]["sig"]
            (r2, s2) = sigs[j]["sig"]
            m1 = sigs[i]["m_hash"]
            m2 = sigs[j]["m_hash"]
            try:
                s_diff_inv = egcd(((s1 - s2) % q), q)
            except ValueError:
                continue
            m_diff = (m1 - m2) % q
            k = (m_diff * s_diff_inv) % q
            r1_inv = egcd(r1, q)
            r2_inv = egcd(r2, q)
            priv_key_cand = dsa_recover_priv_key_from_k(m1, r1_inv, s1, k, g, p, q)
            if mod_exp(g, priv_key_cand, p) == public_key:
                return priv_key_cand

#############################################
# BLEICHENBACHER PKCS PADDING ORACLE ATTACK #
#############################################

def generate_pkcs1_padding_oracle(modulus_bits, private_key):
    def oracle(c):
        m = rsa_decrypt(c, private_key)
        m_bytes = utils.int_to_bytes(m, modulus_bits // 8)
        assert len(m_bytes) * 8 == modulus_bits
        return m_bytes[0] == 0 and m_bytes[1] == 2
    return oracle

def pcks1_padding_attack(oracle, modulus_bits, public_key, cipher):
    N, e = public_key
    B = 2 ** (modulus_bits - 2 * 8)

    # 1. select random s_0 until product c * RSA(s_0) is PKCS1-conforming
    s0 = None
    c0 = None
    while True:
        s0 = secrets.randbelow(N)
        c0 = (cipher * (s0 ** e)) % N
        if oracle(c0):
            break
    print(f"Init s0={s0}")
    
    i = 0
    s_i = None
    M_i = [(2 * B, 3 * B - 1)]
    while True:
        # 2. find s_1 that is PKCS1-conforming
        if i == 0:
            s = math.ceil(N / (3 * B))
            while True:
                c_1 = (c0 * (s ** e)) % N
                if oracle(c_1):
                    break
                s += 1
            s_i = s
        else:
            if len(M_i) == 1:
                start, end_inc = M_i[0]
                r = math.ceil(2 * (end_inc * s_i - 2 * B) // N)
                s = None
                while True:
                    s_start = math.ceil((2 * B + r * N) // end_inc)
                    s_end_inc = (3 * B + r * N) // start
                    if (3 * B + r * N) % start == 0:
                        s_end_inc -= 1
                    r += 1
                    if s_start >= s_end_inc:
                        continue

                    selected = False
                    for s_inner in range(s_start, s_end_inc + 1):
                        c_i = (c0 * (s_inner ** e)) % N
                        if oracle(c_i):
                            s = s_inner
                            selected = True
                            break
                    if selected:
                        break
                s_i = s
            else:
                s = s_i + 1
                while True:
                    c_i = (c0 * (s ** e)) % N
                    if (oracle(c_i)):
                        break
                    s += 1
                s_i = s

        print(f"i={i} Found s_i={s_i}")
        i += 1

        # 3: narrow search space M
        new_unmerged_M = []
        for interval in M_i:
            start, end_inc = interval
            r_start = (start * s_i - 3 * B + 1) // N
            if (start * s_i - 3 * B + 1) % N != 0:
                r_start += 1
            r_end_inc = (end_inc * s_i - 2 * B) // N
            # assert r_start <= r_end_inc
            for r in range(r_start, r_end_inc + 1):
                new_start_opt = (2 * B + r * N) // s_i
                if (2 * B + r * N) % s_i != 0:
                    new_start_opt += 1
                new_end_opt = (3 * B - 1 + r * N) // s_i
                new_start = max(start, new_start_opt)
                new_end_inc = min(end_inc, new_end_opt)
                new_unmerged_M.append((new_start, new_end_inc))
        M_i = merge_intervals(new_unmerged_M)
        print(f"Updated M={M_i}")

        # 4: check if M has narrowed to a single number
        if len(M_i) == 1:
            start, end = M_i[0]
            if start == end:
                return (start * egcd(s0, N)) % N
        
def merge_intervals(M):
    def sort_fn(tup):
        start, end = tup
        return start
    if len(M) == 0:
        return M
    M.sort(key=sort_fn)
    final_intervals = []
    curr_start, curr_end = None, None
    for interval in M:
        if curr_start is None:
            curr_start, curr_end = interval
        else:
            start, end = interval
            if start > curr_end:
                final_intervals.append((curr_start, curr_end))
            else:
                curr_end = end
    if curr_start is not None:
        final_intervals.append((curr_start, curr_end))
    return final_intervals
