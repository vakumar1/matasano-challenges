import library.utilities as utils
import library.aes as aes
import library.prng as prng
import secrets
import base64
import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")

def p1():
    inps = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

    inps = [base64.b64decode(inp) for inp in inps]
    outs = aes.break_random_cbc_oracle(inps)
    outs.sort()
    for out in outs:
        utils.printout(out)

def p2():
    inp = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
    key = utils.ascii_to_bytes("YELLOW SUBMARINE")
    nonce = bytearray(8)
    out = aes.aes_little_endian_ctr_encr_decr(inp, key, nonce)
    utils.printout(out)

def p4():
    inp_file = os.path.join(INPUT_FILES, "20.txt")
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
    inps = [base64.b64decode(inp) for inp in inps]

    nonce = bytearray(8)
    key = secrets.token_bytes(16)
    encr_inps = [aes.aes_little_endian_ctr_encr_decr(inp, key, nonce) for inp in inps]

    outs = aes.break_aes_ctr_encr(encr_inps)
    for out in outs:
        utils.printout(out)

def p5():
    MTwister = prng.MT(42)
    outs = [MTwister.extract_number() for _ in range(10)]
    for out in outs:
        print(out)

def p6():
    out = prng.crack_mt_seed()
    print(out)

def p7():
    MTwister = prng.MT(42)
    MTwisterClone = prng.clone_mt(MTwister)
    identical_out = all([MTwister.extract_number() == MTwisterClone.extract_number() for _ in range(prng.MT.n)])
    print(identical_out)

def main():
    functions = {
        "1": p1,
        "2": p2,
        "4": p4,
        "5": p5,
        "6": p6,
        "7": p7
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
