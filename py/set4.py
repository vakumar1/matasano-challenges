import library.utilities as utils
import library.aes as aes
import library.prng as prng
import library.mac as mac
import random
import secrets
import base64
import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")


def p1():
    inp_file = os.path.join(INPUT_FILES, "20.txt")
    with open(inp_file, "r") as f:
        inp = f.read()
    inp = base64.b64decode(inp)
    nonce = bytearray(8)
    encr, edit = aes.aes_little_endian_ctr_random_encr(inp, nonce)
    utils.printout(aes.break_aes_ctr_random_encr(encr, edit))

def p2():
    out = aes.break_aes_ctr_user_data()
    utils.printout(out)

def p3():
    got_key = aes.break_aes_cbc_keyiv_user_data()
    print(got_key)

def p4():
    inp = utils.ascii_to_bytes("hello world")
    expected = bytes.fromhex("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
    hash = mac.sha1(inp)
    print("SHA1 sanity check: ", expected == hash)

    key = secrets.token_bytes(random.randint(1, 32))
    mac_hash = mac.sha1_mac_gen(key, inp)
    print("Verify correct SHA1 MAC: ", mac.sha1_mac_verify(key, inp, mac_hash))
    tampered = bytearray([mac_hash[0] + 1]) + mac_hash[1:]
    print("Verify invalid SHA1 MAC: ", mac.sha1_mac_verify(key, inp, tampered))

def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4
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