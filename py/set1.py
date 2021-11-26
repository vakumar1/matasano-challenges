from conversions import IntRep
from breakers import SingleByteXOR, RepeatingKeyXOR
from Crypto.Cipher import AES
import sys
import os

INPUT_FILES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "inputs")

def p1():
    # convert hex to base64"
    inp = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    s = IntRep(inp, 16)
    out = s.get_string(64)
    print(out)

def p2():
    # calculate xor
    inp1 = "1c0111001f010100061a024b53535009181c"
    inp2 = "686974207468652062756c6c277320657965"
    s1 = IntRep(inp1, 16)
    s2 = IntRep(inp2, 16)
    s3 = IntRep(s1.get_int() ^ s2.get_int(), 0)
    out = s3.get_string(16)
    print(out)

def p3():
    # implement single byte xor
    inp = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    s = IntRep(inp, 16)
    SBX = SingleByteXOR(16, 2)
    k = SBX.break_enc(s)
    x = SBX.decrypt(s, k)
    print(x.get_ascii())

def p4():
    # break single byte xor
    inp_file = os.path.join(INPUT_FILES, "challenge4_ciphers.txt")
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()

    SBX = SingleByteXOR(16, 2)
    best_prob = -1
    best_inp = IntRep()
    for inp in inps:
        s = IntRep(inp, 16)
        x = SBX.decrypt(s, SBX.break_enc(s))
        prob = SBX.str_prob(x)
        if prob > best_prob:
            best_prob = prob
            best_inp = x
    print(best_inp.get_ascii())

def p5():
    # implement repeating key xor
    inp = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal"
    RKX = RepeatingKeyXOR(16, 2)
    s = IntRep(inp, ascii=True)
    k = IntRep("ICE", ascii=True)
    y = RKX.encrypt(s, k)
    print(y.get_string(16))

def hd():
    # implement hamming distance
    inp1 = "this is a test"
    inp2 = "wokka wokka!!!"
    RKX = RepeatingKeyXOR(16, 2)
    s1 = IntRep(inp1, ascii=True)
    s2 = IntRep(inp2, ascii=True)
    d = RKX.hamming_dist(s1, s2)
    print(d)

def p6():
    # break repeating key xor
    inp_file = os.path.join(INPUT_FILES, "challenge6_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    y = IntRep(inp, 64)
    RKX = RepeatingKeyXOR(16, 2)
    k = RKX.break_enc(y)
    x = RKX.decrypt(y, k)
    print(x.get_ascii())

def p7():
    # decrypt AES-128 ECB
    inp_file = os.path.join(INPUT_FILES, "challenge7_cipher.txt")
    inp = ""
    with open(inp_file, "r") as f:
        inps = f.read().splitlines()
        for inp_str in inps:
            inp += inp_str
    
    y = IntRep(inp, 64)
    AES_obj = AES.new("YELLOW SUBMARINE", AES.MODE_ECB) 
    x = AES_obj.decrypt(y.get_bytes())
    print(str(x, "ascii"))

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
