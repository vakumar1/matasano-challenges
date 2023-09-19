import library.utilities as utils

from http.server import BaseHTTPRequestHandler
import urllib
import requests
import time
import binascii

############
# SHA1 MAC #
############

# return padding: pad to 0 % 512 bits and add input length
def sha1_padding(inp, ml):
    if ml % 512 == 448:
        padding_len = 448
    elif ml % 512 < 448:
        padding_len = 448 - (ml % 512)
    else:
        padding_len = 448 + (512 - (ml % 512))
    assert padding_len % 8 == 0 and padding_len > 0
    padding = bytearray(utils.NULL_BYTE * (padding_len // 8))
    padding[0] = 0x80
    padding += utils.int_to_bytes(ml, 8)
    return padding

def sha1(inp, registers=[], inp_length=0):

    # set initial register values and add padding
    if len(registers) == 0:
        h0 = 0x67452301
        h1 = 0xEFCDAB89
        h2 = 0x98BADCFE
        h3 = 0x10325476
        h4 = 0xC3D2E1F0
        ml = len(inp) * 8
    else:
        h0 = utils.bytes_to_int(registers[0])
        h1 = utils.bytes_to_int(registers[1])
        h2 = utils.bytes_to_int(registers[2])
        h3 = utils.bytes_to_int(registers[3])
        h4 = utils.bytes_to_int(registers[4])
        ml = inp_length
    inp += sha1_padding(inp, ml)
    assert len(inp) % 64 == 0

    # update registers for each 512-bit chunk in input
    chunk_size = 64
    chunks = [inp[i:i + chunk_size] for i in range(0, len(inp), chunk_size)]
    for chunk in chunks:
        word_size = 4
        words = [chunk[i:i + word_size] for i in range(0, chunk_size, word_size)]
        for i in range(16, 80):
            new_word = utils.bytes_xor(words[i - 3], utils.bytes_xor(words[i - 8], utils.bytes_xor(words[i - 14], words[i - 16])))
            new_word = utils.bytes_leftrotate(new_word, 1)
            words.append(new_word)
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        for i in range(80):
            if i <= 19:
                f = (b & c) | (~b & d)
                k = 0x5A827999
            elif i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            tmp = utils.bytes_leftrotate(utils.int_to_bytes(a, 4), 5)
            tmp = (utils.bytes_to_int(tmp) + f + e + k + utils.bytes_to_int(words[i])) % (1 << 32)
            e = d
            d = c
            c = utils.bytes_to_int(utils.bytes_leftrotate(utils.int_to_bytes(b, 4), 30))
            b = a
            a = tmp
        h0 = (h0 + a) % (1 << 32)
        h1 = (h1 + b) % (1 << 32)
        h2 = (h2 + c) % (1 << 32)
        h3 = (h3 + d) % (1 << 32)
        h4 = (h4 + e) % (1 << 32)

    hh = utils.int_to_bytes(h0, 4) + utils.int_to_bytes(h1, 4) + utils.int_to_bytes(h2, 4) + utils.int_to_bytes(h3, 4) + utils.int_to_bytes(h4, 4)
    return hh


def sha1_mac_gen(key, inp):
    return sha1(key + inp)

def sha1_mac_verify(key, inp, mac):
    return sha1(key + inp) == mac

####################################
# SHA1 MAC LENGTH EXTENSION ATTACK #
####################################

def get_sha1_mac_verifier(key):
    def verifier(inp, mac):
        return sha1_mac_verify(key, inp, mac)
    return verifier

def extend_sha1_mac(verifier, mac_hash, inp, extension):
    for key_len in range(1, 33):
        orig_padding = sha1_padding(inp, (key_len + len(inp)) * 8)
        new_inp = inp + orig_padding + extension

        registers = [mac_hash[i:i + 4] for i in range(0, len(mac_hash), 4)]
        inp_length = (key_len + len(inp) + len(orig_padding) + len(extension)) * 8
        new_mac_hash = sha1(extension, registers=registers, inp_length=inp_length)
        if verifier(new_inp, new_mac_hash):
            return new_inp, new_mac_hash
    return utils.NULL_BYTE, utils.NULL_BYTE

###########
# MD4 MAC #
###########

def md4_padding(inp, ml):
    if ml % 512 == 448:
        padding_len = 448
    elif ml % 512 < 448:
        padding_len = 448 - (ml % 512)
    else:
        padding_len = 448 + (512 - (ml % 512))
    assert padding_len % 8 == 0 and padding_len > 0
    padding = bytearray(utils.NULL_BYTE * (padding_len // 8))
    padding[0] = 0x80
    padding += utils.int_to_bytes_little_end(ml, 8)
    return padding

def md4(inp, registers=[], inp_length=0):
    if len(registers) == 0:
        A = 0x67452301
        B = 0xefcdab89
        C = 0x98badcfe
        D = 0x10325476
        ml = len(inp) * 8
    else:
        A = utils.bytes_to_int_little_end(registers[0])
        B = utils.bytes_to_int_little_end(registers[1])
        C = utils.bytes_to_int_little_end(registers[2])
        D = utils.bytes_to_int_little_end(registers[3])
        ml = inp_length
    inp += md4_padding(inp, ml)
    assert len(inp) % 64 == 0

    # update registers for each 512-bit chunk in input

    def F(x, y, z):
        return (x & y) | (~x & z)
    def G(x, y, z):
        return (x & y) | (x & z) | (y & z)
    def H(x, y, z):
        return x ^ y ^ z
    
    chunk_size = 64
    chunks = [inp[i:i + chunk_size] for i in range(0, len(inp), chunk_size)]
    for chunk in chunks:
        AA = A
        BB = B
        CC = C
        DD = D

        word_size = 4
        words = [utils.bytes_to_int(chunk[i:i + word_size][::-1]) for i in range(0, chunk_size, word_size)]

        # round 1
        def round1(X1, X2, X3, X4, k, s):
            summ = utils.int_to_bytes((X1 + F(X2, X3, X4) + words[k]) % (1 << 32), 4)
            return utils.bytes_to_int(utils.bytes_leftrotate(summ, s))
        A = round1(A, B, C, D, 0, 3)
        D = round1(D, A, B, C, 1, 7)
        C = round1(C, D, A, B, 2, 11)
        B = round1(B, C, D, A, 3, 19)

        A = round1(A, B, C, D, 4, 3)
        D = round1(D, A, B, C, 5, 7)
        C = round1(C, D, A, B, 6, 11)
        B = round1(B, C, D, A, 7, 19)

        A = round1(A, B, C, D, 8, 3)
        D = round1(D, A, B, C, 9, 7)
        C = round1(C, D, A, B, 10, 11)
        B = round1(B, C, D, A, 11, 19)

        A = round1(A, B, C, D, 12, 3)
        D = round1(D, A, B, C, 13, 7)
        C = round1(C, D, A, B, 14, 11)
        B = round1(B, C, D, A, 15, 19)

        # round 2
        def round2(X1, X2, X3, X4, k, s):
            summ = utils.int_to_bytes((X1 + G(X2, X3, X4) + words[k] + 0x5A827999) % (1 << 32), 4)
            return utils.bytes_to_int(utils.bytes_leftrotate(summ, s))
        
        A = round2(A, B, C, D, 0, 3)
        D = round2(D, A, B, C, 4, 5)
        C = round2(C, D, A, B, 8, 9)
        B = round2(B, C, D, A, 12, 13)

        A = round2(A, B, C, D, 1, 3)
        D = round2(D, A, B, C, 5, 5)
        C = round2(C, D, A, B, 9, 9)
        B = round2(B, C, D, A, 13, 13)

        A = round2(A, B, C, D, 2, 3)
        D = round2(D, A, B, C, 6, 5)
        C = round2(C, D, A, B, 10, 9)
        B = round2(B, C, D, A, 14, 13)

        A = round2(A, B, C, D, 3, 3)
        D = round2(D, A, B, C, 7, 5)
        C = round2(C, D, A, B, 11, 9)
        B = round2(B, C, D, A, 15, 13)

        # round3
        def round3(X1, X2, X3, X4, k, s):
            summ = utils.int_to_bytes((X1 + H(X2, X3, X4) + words[k] + 0x6ED9EBA1) % (1 << 32), 4)
            return utils.bytes_to_int(utils.bytes_leftrotate(summ, s))
        
        A = round3(A, B, C, D, 0, 3)
        D = round3(D, A, B, C, 8, 9)
        C = round3(C, D, A, B, 4, 11)
        B = round3(B, C, D, A, 12, 15)

        A = round3(A, B, C, D, 2, 3)
        D = round3(D, A, B, C, 10, 9)
        C = round3(C, D, A, B, 6, 11)
        B = round3(B, C, D, A, 14, 15)

        A = round3(A, B, C, D, 1, 3)
        D = round3(D, A, B, C, 9, 9)
        C = round3(C, D, A, B, 5, 11)
        B = round3(B, C, D, A, 13, 15)

        A = round3(A, B, C, D, 3, 3)
        D = round3(D, A, B, C, 11, 9)
        C = round3(C, D, A, B, 7, 11)
        B = round3(B, C, D, A, 15, 15)

        A = (A + AA) % (1 << 32)
        B = (B + BB) % (1 << 32)
        C = (C + CC) % (1 << 32)
        D = (D + DD) % (1 << 32)

    return utils.int_to_bytes_little_end(A, 4) + utils.int_to_bytes_little_end(B, 4) + \
                utils.int_to_bytes_little_end(C, 4) + utils.int_to_bytes_little_end(D, 4)


def md4_mac_gen(key, inp):
    return md4(key + inp)

def md4_mac_verify(key, inp, mac):
    return md4(key + inp) == mac

###################################
# MD4 MAC LENGTH EXTENSION ATTACK #
###################################

def get_md4_mac_verifier(key):
    def verifier(inp, mac):
        return md4_mac_verify(key, inp, mac)
    return verifier

def extend_md4_mac(verifier, mac_hash, inp, extension):
    for key_len in range(1, 33):
        orig_padding = md4_padding(inp, (key_len + len(inp)) * 8)
        new_inp = inp + orig_padding + extension

        registers = [mac_hash[i:i + 4] for i in range(0, len(mac_hash), 4)]
        inp_length = (key_len + len(inp) + len(orig_padding) + len(extension)) * 8
        new_mac_hash = md4(extension, registers=registers, inp_length=inp_length)
        if verifier(new_inp, new_mac_hash):
            return new_inp, new_mac_hash
    return utils.NULL_BYTE, utils.NULL_BYTE

####################
# HMAC TIMING LEAK #
####################

class HMACHandler(BaseHTTPRequestHandler):
    def __init__(self, sleep_time, key, *args, **kwargs):
        self.key = key
        self.sleep_time = sleep_time
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_url = urllib.parse.urlparse(self.path)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        file_param = utils.ascii_to_bytes(query_params.get('file', [''])[0])
        hmac_param = bytes.fromhex(query_params.get('hmac', [''])[0])
        if parsed_url.path == '/verify' and file_param and hmac_param:
            verified = self.slow_sha1_hmac_verify(file_param, hmac_param)
            result = "Correct.\n" if verified else "Incorrect.\n"
            self.send_response(200 if verified else 500)
        else:
            result = "Not found.\n"
            self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(result.encode('utf-8'))

    def slow_sha1_hmac_verify(self, inp, mac):
        hmac = sha1_hmac_gen(self.key, inp)
        for i in range(len(mac)):
            if hmac[i] != mac[i]:
                return False
            time.sleep(self.sleep_time)
        return True

def sha1_hmac_gen(key, inp):
    opad = bytearray([0x5C] * len(key))
    ipad = bytearray([0x36] * len(key))
    okey = utils.bytes_xor(key, opad)
    ikey = utils.bytes_xor(key, ipad)
    return sha1(okey + sha1(ikey + inp))

def break_slow_sha1_hmac(server_url, file):
    mac_len = 20
    curr_mac = bytearray(mac_len)
    for i in range(mac_len):
        slowest_byte, slowest_time = 0, 0
        copy_mac = curr_mac[:]
        for b in range(0, 256):
            copy_mac[i] = b
            start = time.time()
            try:
                requests.get(server_url, params={
                    "file": file,
                    "hmac": binascii.hexlify(copy_mac).decode('utf-8')
                })
            except requests.exceptions.HTTPError:
                pass
            end = time.time()
            diff = end - start
            if diff > slowest_time:
                slowest_byte, slowest_time = b, diff
        curr_mac[i] = slowest_byte
    try:
        res = requests.get(server_url, params={
            "file": file,
            "hmac": binascii.hexlify(curr_mac).decode('utf-8')
        })
    except requests.exceptions.HTTPError:
        pass
    return res.status_code == 200
