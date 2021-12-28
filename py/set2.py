import utilities as utils
import breakers as brk
import base64
import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")

def p1():
    # PKCS7 pad input
    inp = utils.ascii_to_bytes("YELLOW SUBMARINE")
    out = utils.pkcs7_pad(inp, 20)
    print(out)

def p2():
    # AES CBC mode decrypt
    inp_file = os.path.join(INPUT_FILES, "challenge10_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    inp = base64.b64decode(inp)
    key = "YELLOW SUBMARINE"
    iv = utils.NULL_BYTE * len(key)
    out = brk.aes_cbc_decrypt(inp, key, iv)
    utils.printout(out)

def p3():
    reps = 10000
    correct = 0
    for _ in range(reps):
        actual, predicted = brk.break_random_aes_encryption()
        if actual == predicted:
            correct += 1
    print("Correct: ", correct, " out of ", reps)

def p4():
    inp = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    block_size = brk.verify_aes_ecb_block_size(inp)
    out = brk.break_aes_ecb_encryption(inp)
    utils.printout(out)
    
def pars():
    inp1 = "foo=bar&baz=qux&zap=zazzle"
    inp2 = "foo@bar.com"
    out1 = utils.k_v_parser(inp1)
    out2 = utils.generate_profile(inp2)
    print(out1)
    print(out2)

def p5():
    out = brk.break_aes_user_role()
    print(out)

def p6():
    inp = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    out = brk.break_aes_ecb_random_encryption(inp)
    utils.printout(out)

def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4,
        "pars": pars,
        "5": p5,
        "6": p6
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