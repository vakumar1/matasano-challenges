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
    inps = {
        "hello world": "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
        "A" * 100: "7a4a9ae537ebbbb826b1060e704490ad0f365ead"
    }
    for inp, expected in inps.items():
        inp = utils.ascii_to_bytes(inp)
        expected = bytes.fromhex(expected)
        hash = mac.sha1(inp)
        print("SHA1 sanity check: ", expected == hash)

    key = secrets.token_bytes(random.randint(1, 32))
    mac_hash = mac.sha1_mac_gen(key, inp)
    print("Verify correct SHA1 MAC: ", mac.sha1_mac_verify(key, inp, mac_hash))
    tampered = bytearray([mac_hash[0] + 1]) + mac_hash[1:]
    print("Verify invalid SHA1 MAC: ", mac.sha1_mac_verify(key, inp, tampered))

def p5():
    inp = utils.ascii_to_bytes("comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon")
    key = secrets.token_bytes(random.randint(1, 32))
    mac_hash = mac.sha1_mac_gen(key, inp)

    mac_verifier = mac.get_sha1_mac_verifier(key)
    extension = utils.ascii_to_bytes(";admin=true")
    new_inp, new_mac_hash = mac.extend_sha1_mac(mac_verifier, mac_hash, inp, extension)
    print("Verify correct extended SHA1 MAC: ", mac.sha1_mac_verify(key, new_inp, new_mac_hash))
    utils.printout(new_inp)

def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4,
        "5": p5
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