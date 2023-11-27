import library.aes as aes
import library.mac as mac
import library.utilities as utils

import secrets
import hashlib, hmac
from Crypto.Util import number

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
    
def rsa_gen_params():
    p = number.getPrime(1024)
    while p % 3 != 2:
        p = number.getPrime(1024)
    q = number.getPrime(1024)
    while q % 3 != 2:
        q = number.getPrime(1024)
    N = p * q
    et = (p - 1) * (q - 1)
    e = 3
    d = (egcd(e, et)) % et
    return (N, e), (N, d)

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
