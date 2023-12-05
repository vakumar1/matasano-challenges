import library.public_key as pk
import library.utilities as utils

import sys

def p1():
    m = utils.bytes_to_int(utils.ascii_to_bytes("This is the message."))
    oracle = pk.RSADecryptionOracle()
    public_key = oracle.key()
    c = pk.rsa_encrypt(m, public_key)

    # break oracle
    m_ = pk.break_rsa_oracle(c, oracle)
    print(f"Decryption successful: {m == m_}. Decrypted message: {utils.bytes_to_ascii(utils.int_to_bytes(m_))}")

def main():
    functions = {
        "1": p1,
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
