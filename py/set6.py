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

def main():
    functions = {
        "1": p1,
        "2": p2,
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
