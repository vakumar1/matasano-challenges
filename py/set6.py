import library.public_key as pk
import library.utilities as utils

import hashlib

import sys

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
    public_key, private_key = pk.rsa_gen_params(e=3)
    m = utils.ascii_to_bytes("This is the message.")
    signature = pk.rsa_sign_sha256(m, private_key)
    correct_verified = pk.verify_rsa_signature_sha256(m, signature, public_key)
    incorrect_verified = pk.verify_rsa_signature_sha256(utils.ascii_to_bytes("This is the incorrect message"), signature, public_key)
    print(f"Correct signature correctly verifies: {correct_verified}")
    print(f"Incorrect signature correctly does not verify: {incorrect_verified}")

    m = utils.ascii_to_bytes("hi mom")
    forged_signature = pk.create_forged_pkcs1_signature(m)
    verified = pk.verify_rsa_signature_sha256(m, forged_signature, public_key)
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


def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
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
