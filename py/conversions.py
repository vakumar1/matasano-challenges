import base64
from binascii import hexlify, unhexlify

base_dicts = {
    2: "01",
    10: "0123456789",
    16: "0123456789abcdef",
    64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
}

def ascii_to_hex(s):
    # return hex string of ASCII string S
    return hexlify(s.encode()).decode()

def base_to_int(b, base):
    # return integer of base string B in BASE
    return int(b, base)

def base64_to_int(b):
    # return integer of base string B in base64
    h = base64.b64decode(b).hex()
    return int(h, 16)

def int_to_base(x, base):
    # return base str of integer X in BASE
    if x == 0:
        return "0"
    if base == 2:
        return bin(x)[2:]
    elif base == 10:
        return str(x)
    elif base == 16:
        return hex(x)[2:]
    else:
        num_str = ""
        base_key = base_dicts[base]
        curr = x
        while curr > 0:
            digit = base_key[curr % base]
            curr = curr // base
            num_str = digit + num_str
        return num_str

def hex_to_bytes(h):
    # return bytes of hex string H
    if len(h) % 2 != 0:
        h = "0" + h
    return unhexlify(h)

def hex_to_ascii(h):
    # return ASCII string of hex string H
    if len(h) % 2 == 1:
        h = "0" + h
    try:
        return bytes.fromhex(h).decode("ASCII")
    except UnicodeDecodeError:
        return ""

def extend(chunk_str, chunk_size, length):
    # return extension of CHUNK_STR to LENGTH (each chunk has length CHUNK_SIZE)
    while len(chunk_str) < chunk_size:
        chunk_str = "0" + chunk_str
    base_str = ""
    for i in range(length):
        base_str += chunk_str[i % chunk_size]
    return base_str
