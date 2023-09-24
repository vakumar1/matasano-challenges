import library.aes as aes
import library.mac as mac
import library.utilities as utils

import secrets
import hashlib

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
    def __init__(self, g_fn, injected_A, s):
        # parameterize attack by g_fn (computes injected g as a function of p), value to inject as A, resulting secret
        self.g_fn = g_fn
        self.A = injected_A
        self.s = s

    def inject_init_msg_sender(self, p, g):
        self.p = p
        return p, self.g_fn(p)
    
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
    
