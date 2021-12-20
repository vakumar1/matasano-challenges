import conversions as cnv
import breakers as brk
from Crypto.Cipher import AES
import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")

def p1():
    # convert hex to base64"
    inp = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    x = cnv.base_to_int(inp, 16)
    out = cnv.int_to_base(x, 64)
    print(out)

def p2():
    # calculate xor
    inp1 = "1c0111001f010100061a024b53535009181c"
    inp2 = "686974207468652062756c6c277320657965"
    x1 = cnv.base_to_int(inp1, 16)
    x2 = cnv.base_to_int(inp2, 16)
    x3 = x1 ^ x2
    out = cnv.int_to_base(x3, 16)
    print(out)

def p3():
    # implement single byte xor
    inp = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    k = brk.sb_xor_break_enc(inp)
    x = brk.sb_xor_decrypt(inp, k)
    out = cnv.hex_to_ascii(x)
    print(out)

def p4():
    # break single byte xor
    inp_file = os.path.join(INPUT_FILES, "challenge4_ciphers.txt")
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()

    best_prob = -1
    best_inp = 0
    for inp in inps:
        k = brk.sb_xor_break_enc(inp)
        x = brk.sb_xor_decrypt(inp, k)
        prob = brk.str_prob(x)
        if prob > best_prob:
            best_prob = prob
            best_inp = x
    out = cnv.hex_to_ascii(best_inp)
    print(out)

def p5():
    # implement repeating key xor
    inp1 = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    inp2 = "ICE"
    x = cnv.ascii_to_hex(inp1)
    k = cnv.ascii_to_hex(inp2)
    out = brk.rk_xor_encrypt(x, k)
    print(out)

def hd():
    # implement hamming distance
    inp1 = "this is a test"
    inp2 = "wokka wokka!!!"
    h1 = cnv.ascii_to_hex(inp1)
    h2 = cnv.ascii_to_hex(inp2)
    out = brk.hamming_dist(h1, h2)
    print(out)

def p6():
    # break repeating key xor
    inp_file = os.path.join(INPUT_FILES, "challenge6_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    i = cnv.base64_to_int(inp)
    y = cnv.int_to_base(i, 16)
    k = brk.rk_xor_break(y)
    x = brk.rk_xor_decrypt(y, k)
    out = cnv.hex_to_ascii(x)
    print(out)

def p7():
    # decrypt AES-128 ECB
    inp_file = os.path.join(INPUT_FILES, "challenge7_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    
    i = cnv.base64_to_int(inp)
    h = cnv.int_to_base(i, 16)
    y = cnv.hex_to_bytes(h)
    AES_obj = AES.new("YELLOW SUBMARINE", AES.MODE_ECB) 
    x = AES_obj.decrypt(y)
    out = str(x, "ascii")

def p8():
    # detect AES-128 ECB
    inp_file = os.path.join(INPUT_FILES, "challenge8_ciphers.txt")
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()

    blocksize = 32
    repeated_block_ciphers = {}
    for index, inp_str in enumerate(inps):
        passed_blocks = set()
        repeated_blocks = set()
        for i in range(0, len(inp_str), blocksize):
            block = inp_str[i:i + blocksize]
            if block in passed_blocks:
                repeated_blocks.add(block)
            passed_blocks.add(block)
        
        num_repeated = len(repeated_blocks)
        if num_repeated > 0:
            repeated_block_ciphers[index] = num_repeated
    print("Ciphers with repeating blocks:")
    print("<Cipher>:<Repeated Block Count>")
    print(repeated_block_ciphers)


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
