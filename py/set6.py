import library.public_key as pk
import library.utilities as utils

import hashlib
import binascii
import base64
import math

import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")

def p1():
    m = utils.bytes_to_int(utils.ascii_to_bytes("This is the message."))
    oracle = pk.RSADecryptionOracle()
    public_key = oracle.key()
    c = pk.rsa_encrypt(m, public_key)

    # break oracle
    m_ = pk.break_rsa_oracle(c, oracle)
    print(f"Decryption successful: {m == m_}. Decrypted message: {utils.bytes_to_ascii(utils.int_to_bytes(m_))}")

def p2():
    # test rsa signature (w/ pkcs1.5 padding)
    rsa_bits, public_key, private_key = pk.rsa_gen_params(factor_mod_bits=2048, e=3)
    m = utils.ascii_to_bytes("This is the message.")
    signature = pk.rsa_sign_sha256(m, rsa_bits, private_key)
    correct_verified = pk.verify_rsa_signature_sha256(m, signature, rsa_bits, public_key)
    incorrect_verified = pk.verify_rsa_signature_sha256(utils.ascii_to_bytes("This is the incorrect message"), signature, rsa_bits, public_key)
    print(f"Correct signature correctly verifies: {correct_verified}")
    print(f"Incorrect signature correctly does not verify: {incorrect_verified}")

    m = utils.ascii_to_bytes("hi mom")
    forged_signature = pk.create_forged_pkcs1_signature(m, rsa_bits)
    verified = pk.verify_rsa_signature_sha256(m, forged_signature, rsa_bits, public_key)
    print(f"Forged signature correctly verified: {verified}")

def p3():
    # test DSA protocol
    m = utils.ascii_to_bytes("This is the message.")
    (priv_key, pub_key) = pk.dsa_gen_keys(pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    correct_sig = pk.dsa_sign_message(m, priv_key, pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    correct_ver = pk.dsa_verify_message(m, correct_sig, pub_key, pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    incorrect_sig = pk.dsa_sign_message(utils.ascii_to_bytes("This is not the message."), priv_key, pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    incorrect_ver = pk.dsa_verify_message(m, incorrect_sig, pub_key, pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    print(f"Correct message correctly verifies: {correct_ver}")
    print(f"Incorrect message correctly does not verify: {incorrect_ver}")

    # recover private key from message
    m_hash_num = 0xd2d0714f014a9784047eaeccf956520045c45265
    pub_key = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
    sig = (548099063082341131477253921760299949438196259240, 857042759984254168557880549501802188789837994940)
    priv_key = pk.dsa_recover_priv_key_brute_force_k(m_hash_num, sig, pub_key, pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    print(f"Recovered DSA private key: {priv_key}")

def p4():
    inp_file = os.path.join(INPUT_FILES, "44.txt")
    sigs = []
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for i in range(len(inps) // 4):
            msg = inps[4 * i][5:]
            s = int(inps[4 * i + 1][3:])
            r = int(inps[4 * i + 2][3:])
            m_hash = int(inps[4 * i + 3][3:], 16)
            sigs.append({
                "sig": (r, s),
                "m_hash": m_hash
            })
    
    public_key = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
    priv_key = pk.desa_recover_priv_key_repeated_k(sigs, public_key, pk.DSA_G, pk.DSA_P, pk.DSA_Q)
    priv_key_hex_str = utils.int_to_hex_bytes(priv_key)
    h = hashlib.sha1()
    h.update(priv_key_hex_str)
    priv_key_hash = utils.bytes_to_hex_str(h.digest())
    print(f"Recovered DSA private key (hash): {priv_key_hash}")

def p5():
    rsa_bits, pub_key, priv_key = pk.rsa_gen_params()
    m = utils.bytes_to_int(base64.b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="))
    c = pk.rsa_encrypt(m, pub_key)
    oracle = pk.get_rsa_even_odd_oracle(priv_key)
    dec_m = pk.break_rsa_even_odd_oracle(oracle, rsa_bits, pub_key, c)
    print(f"Recovered plaintext message from RSA even/odd oracle: {dec_m}")

def p7():
    rsa_bits, pub_key, priv_key = pk.rsa_gen_params(128)
    modulus_bits = 2 * rsa_bits
    m = utils.ascii_to_bytes("kick it, CC")
    padded_m = utils.pkcs1_pad(m, modulus_bits // 8)
    c = pk.rsa_encrypt(utils.bytes_to_int(padded_m), pub_key)
    oracle = pk.generate_pkcs1_padding_oracle(modulus_bits, priv_key)
    m_ = pk.pcks1_padding_attack(oracle, modulus_bits, pub_key, c)
    print(f"Recovered plaintext message from Bleichenbacher attack on PKCS1 oracle: {utils.bytes_to_ascii(utils.int_to_bytes(m_, modulus_bits * 8))}")

def p8():
    rsa_bits, pub_key, priv_key = pk.rsa_gen_params(384)
    modulus_bits = 2 * rsa_bits
    m = utils.ascii_to_bytes("This is a much longer message than in p6")
    padded_m = utils.pkcs1_pad(m, modulus_bits // 8)
    c = pk.rsa_encrypt(utils.bytes_to_int(padded_m), pub_key)
    oracle = pk.generate_pkcs1_padding_oracle(modulus_bits, priv_key)
    m_ = pk.pcks1_padding_attack(oracle, modulus_bits, pub_key, c)
    print(f"Recovered plaintext message from Bleichenbacher attack on PKCS1 oracle: {utils.bytes_to_ascii(utils.int_to_bytes(m_, modulus_bits * 8))}")

def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4,
        "5": p5,
        "7": p7,
        "8": p8,
    }

    if len(sys.argv) < 2:
        execute = functions.keys()
    else:
        execute = sys.argv[1:]
    for func in execute:
        if func not in functions:
            continue
        print(f"================================= {func} =================================")
        functions[func]()

if __name__ == "__main__":
    main()
