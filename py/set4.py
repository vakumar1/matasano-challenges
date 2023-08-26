import library.utilities as utils
import library.aes as aes
import library.prng as prng
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


def main():
    functions = {
        "1": p1,
    }

    if len(sys.argv) < 2:
        execute = functions.keys()
    else:
        execute = sys.argv[1:]
    for func in execute:
        print(f"================================= {func} =================================")
        functions[func]()

if __name__ == "__main__":
    main()