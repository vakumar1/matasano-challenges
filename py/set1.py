import library.utilities as utils
import library.xor as xor
import library.aes as aes
import base64
import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")

def p1():
    # convert hex to base64"
    inp = bytes.fromhex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
    utils.printout(inp, 64)

def p2():
    # calculate xor
    inp1 = bytes.fromhex("1c0111001f010100061a024b53535009181c")
    inp2 = bytes.fromhex("686974207468652062756c6c277320657965")
    out = utils.bytes_xor(inp1, inp2)
    utils.printout(out, 16)

def p3():
    # implement single byte xor
    inp = bytes.fromhex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
    k = xor.sb_xor_break_enc(inp)
    x = xor.sb_xor_decrypt(inp, k)
    utils.printout(x)

def p4():
    # break single byte xor
    inp_file = os.path.join(INPUT_FILES, "challenge4_ciphers.txt")
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
    inps = [bytes.fromhex(inp) for inp in inps]

    best_prob = -1
    best_inp = 0
    for inp in inps:
        k = xor.sb_xor_break_enc(inp)
        x = xor.sb_xor_decrypt(inp, k)
        prob = utils.str_prob(x)
        if prob > best_prob:
            best_prob = prob
            best_inp = x
    utils.printout(best_inp)

def p5():
    # implement repeating key xor
    inp1 = utils.ascii_to_bytes("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal")
    inp2 = utils.ascii_to_bytes("ICE")
    out = xor.rk_xor_encrypt(inp1, inp2)
    utils.printout(out, 16)

def hd():
    # implement hamming distance
    inp1 = utils.ascii_to_bytes("this is a test")
    inp2 = utils.ascii_to_bytes("wokka wokka!!!")
    out = utils.hamming_dist(inp1, inp2)
    print(out)

def p6():
    # break repeating key xor
    inp_file = os.path.join(INPUT_FILES, "challenge6_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    inp = base64.b64decode(inp)
    k = xor.rk_xor_break(inp)
    out = xor.rk_xor_decrypt(inp, k)
    utils.printout(out)

def p7():
    # decrypt AES-128 ECB
    inp_file = os.path.join(INPUT_FILES, "challenge7_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    inp = base64.b64decode(inp)
    key = utils.ascii_to_bytes("YELLOW SUBMARINE")
    out = aes.aes_ebc_decrypt(inp, key)
    utils.printout(out)

def p8():
    # detect AES-128 ECB
    inp_file = os.path.join(INPUT_FILES, "challenge8_ciphers.txt")
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
    inps = [bytes.fromhex(inp) for inp in inps]

    block_size = 16
    repeated_block_ciphers = []
    for index, inp in enumerate(inps):
        if aes.detect_aes_ebc(inp, block_size):
            repeated_block_ciphers.append(index)
    print("Ciphers with repeating blocks:", repeated_block_ciphers)


def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4,
        "5": p5,
        "hd": hd,
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
