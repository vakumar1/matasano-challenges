import library.utilities as utils
import library.aes as aes
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
    key = utils.ascii_to_bytes("YELLOW SUBMARINE")
    iv = utils.NULL_BYTE * len(key)
    out = aes.aes_cbc_decrypt(inp, key, iv)
    utils.printout(out)

def p3():
    reps = 10000
    correct = 0
    for _ in range(reps):
        actual, predicted = aes.break_random_aes_encryption()
        if actual == predicted:
            correct += 1
    print("Correct: ", correct, " out of ", reps)

def p4():
    inp = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    block_size = aes.verify_aes_ecb_block_size(inp)
    out = aes.break_aes_ecb_encryption(inp)
    utils.printout(out)

def p5():
    out = aes.break_aes_user_role()
    print(out)

def p6():
    inp = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    out = aes.break_aes_ecb_random_encryption(inp)
    utils.printout(out)

def p7():
    inp1 = utils.ascii_to_bytes("ICE ICE BABY\x04\x04\x04\x04")
    inp2 = utils.ascii_to_bytes("ICE ICE BABY\x05\x05\x05\x05")
    inp3 = utils.ascii_to_bytes("ICE ICE BABY\x01\x02\x03\x04")
    
    out1 = utils.remove_pkcs7_pad(inp1, 16)
    utils.printout(out1)
    
    try:
        out2 = utils.remove_pkcs7_pad(inp2, 16)
    except ValueError as e:
        print(e)
    
    try:
        out3 = utils.remove_pkcs7_pad(inp3, 16)
    except ValueError as e:
        print(e)

def p8():
    out = aes.break_aes_cbc_user_data()
    utils.printout(out)

def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4,
        "5": p5,
        "6": p6,
        "7": p7,
        "8": p8
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
