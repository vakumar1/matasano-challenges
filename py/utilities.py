import base64
import math

NULL_BYTE = bytes.fromhex("00")

CHAR_FREQS = {
    'a': 0.08167,
    'b': 0.01492, 
    'c': 0.02782, 
    'd': 0.04253, 
    'e': 0.12702, 
    'f': 0.02228, 
    'g': 0.02015, 
    'h': 0.06094, 
    'i': 0.06966, 
    'j': 0.00153, 
    'k': 0.00772, 
    'l': 0.04025, 
    'm': 0.02406, 
    'n': 0.06749,
    'o': 0.07507,
    'p': 0.01929,
    'q': 0.00095,
    'r': 0.05987,
    's': 0.06327,
    't': 0.09056,
    'u': 0.02758,
    'v': 0.00978,
    'w': 0.02360,
    'x': 0.00150,
    'y': 0.01974,
    'z': 0.00074,
    ' ': 0.15
}

###############
# CONVERSIONS #
###############

def bytes_to_ascii(b):
    # convert bytes B to ASCII (if not possible -> empty string "")
    return b.decode("ASCII", "replace")

def ascii_to_bytes(s):
    # convert ASCII S to bytes
    return bytes(s, "ascii")

def bytes_to_int(b):
    # convert bytes B to int
    return int.from_bytes(b, "big")

def int_to_bytes(i, length=0):
    # convert int I to bytes with LENGTH
    if length == 0:
        length = math.ceil(math.log(i, 16))
    return int.to_bytes(i, length, "big")

#################
# PROCESS BYTES #
#################

def prepad_null_bytes(b, length):
    # prepad B with null byte until has LENGTH
    diff = length - len(b)
    return NULL_BYTE * diff + b

def byte_extend(chunk, chunk_size, length):
    # return extension of CHUNK to LENGTH (each chunk has length CHUNK_SIZE)
    total_chunk = prepad_null_bytes(chunk, chunk_size)
    extended = bytearray()
    for i in range(length):
        extended.append(total_chunk[i % chunk_size])
    return extended

def pkcs7_pad(b, block_size):
    # PKCS7 pad B with BLOCK_SIZE
    diff = block_size - (len(b) % block_size)
    return b + int_to_bytes(diff, 1) * diff

def remove_pkcs7_pad(b, block_size):
    pad_count = b[-1]
    if pad_count > block_size:
        return bytearray()

    pad_bytes = b[-pad_count:]
    for pad_byte in pad_bytes:
        if pad_byte != pad_count:
            return bytearray()
    return b[:-pad_count]



#########
# USERS #
#########

def k_v_parser(s):
    # get profile (dict) of encoding (string)
    profile = {}
    pairs = s.split("&")
    for item in pairs:
        key, value = item.split("=")
        profile[key] = value
    return profile

def generate_profile(email):
    # generator user profile encoding (string) from email
    if ("&" in email) or ("=" in email):
        return ""
    uid = "10"
    role = "user"
    profile_encoding = "email=" + email + "&uid=" + uid + "&role=" + role
    return profile_encoding

def generate_user_data(data):
    stripped = data.translate({ord(c): None for c in ";="})
    return "comment1=cooking%20MCs;userdata=" + stripped + \
        ";comment2=%20like%20a%20pound%20of%20bacon"


#################
# OTHER HELPERS #
#################

def printout(out, base=0):
    # print OUT as string in BASE (default to 0 -> ASCII)
    if base == 0:
        encoded = out
    elif base == 16:
        encoded = base64.b16encode(out)
    elif base == 64:
        encoded = base64.b64encode(out)
    print(bytes_to_ascii(encoded))

def bytes_xor(b1, b2):
    # XOR bytearrays B1 and B2
    result = bytearray()
    for x1, x2 in zip(b1, b2):
        result.append(x1 ^ x2)
    return result

def str_prob(x):
    # return the probability of PT X
    eng_str = bytes_to_ascii(x)
    score = 0.0
    for c in eng_str:
        if c in CHAR_FREQS:
            score += CHAR_FREQS[c.lower()]
    if len(eng_str) == 0:
        return score
    else:
        return score / len(eng_str)

def hamming_dist(b1, b2):
    # return hamming distance between B1 and B2
    xor = bytes_xor(b1, b2)
    dist = 0
    binary = bin(int.from_bytes(xor, "big"))[2:]
    for c in binary:
        if c != "0":
            dist += 1
    return dist
