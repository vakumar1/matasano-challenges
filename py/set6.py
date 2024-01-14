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
    # test RSA signature algorithm
    public_key, private_key = pk.rsa_gen_params(e=3)
    m = utils.ascii_to_bytes("This is the message.")
    signature = pk.rsa_sign_sha256(m, private_key)
    signature_bytes = utils.int_to_bytes(signature, pk.RSA_MOD_BYTES)
    h = hashlib.sha256()
    h.update(signature_bytes)
    signature_hash = h.digest()
    print(f"RSA signing successful: {pk.verify_rsa_signature_sha256(m, signature, public_key)}")

    # test pkcs1.5 padding + removal
    padded_m = pk.pkcs1_signature_pad(m, signature, pk.RSA_MOD_BYTES)
    ret_m, ret_signature_hash = pk.faulty_remove_pkcs1_mac_pad(padded_m)
    print(f"PKCS1.5 padding successful: {signature_hash == ret_signature_hash}")

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
