import utilities as utils
from Crypto.Cipher import AES
import base64
import secrets
import random

###################
# SINGLY BYTE XOR #
###################

def sb_xor_encrypt(x, k):
    # encrypt PT X with single byte key K
    k_ext = utils.byte_extend(k, 1, len(x))
    y = utils.bytes_xor(x, k_ext)
    return y

def sb_xor_decrypt(y, k):
    # decrypt CT Y with single byte key K
    k_ext = utils.byte_extend(k, 1, len(y))
    x = utils.bytes_xor(y, k_ext)
    return x

def sb_xor_break_enc(y):
    # return best single byte key of CT Y
    best_prob = 0.0
    best_key = utils.int_to_bytes(0, 1)
    for i in range(16 ** 2):
        k = utils.int_to_bytes(i, 1)
        x = sb_xor_decrypt(y, k)
        prob = utils.str_prob(x)
        if prob > best_prob:
            best_prob = prob
            best_key = k
    return best_key

#####################
# REPEATING KEY XOR #
#####################

def rk_xor_encrypt(x, k):
    # encrypt PT X with repeating key K
    k_ext = utils.byte_extend(k, len(k), len(x))
    y = utils.bytes_xor(x, k_ext) 
    return y

def rk_xor_decrypt(y, k):
    # decrypt CT Y with repeating key K
    k_ext = utils.byte_extend(k, len(k), len(y))
    x = utils.bytes_xor(y, k_ext)
    return x

def rk_xor_break(y):
    # return the best repeating key
    # split y into key_size blocks
    key_size = get_key_size(y, 2, 40, 10)
    blocks = [bytearray() for _ in range(key_size)]
    for i in range(len(y)):
        blocks[i % key_size].append(y[i])

    # for each hex block, find the best single byte key and append to key
    key = bytearray()
    for block in blocks:
        block_key = sb_xor_break_enc(block)
        key.append(int.from_bytes(block_key, "big"))
    return key

def get_key_size(y, start, end, num_blocks):
    # return the best key_size for CT Y (hex string)
    # start: min key size
    # end: max key size
    # num blocks: how many blocks of CT Y to compare
    best_dist = float("inf")
    best_size = 0
    end = min(end, int(len(y) / num_blocks) - 1)
    for size in range(start, end):
        # split Y into blocks
        blocks = []
        for i in range(num_blocks):
            block = y[i * size:(i + 1) * size]
            blocks.append(block)

        # get total hamming distance for all blocks
        dist = 0.0
        for i in range(num_blocks):
            for j in range(i):
                dist += utils.hamming_dist(blocks[i], blocks[j])

        # update best key size using normalized distance
        norm_dist = dist / size
        if norm_dist < best_dist:
            best_dist = norm_dist
            best_size = size
    return best_size

####################################
# AES: BASIC ENCRYPTION/DECRYPTION #
####################################

def aes_ebc_encrypt(x, k):
    # encrypt X (bytes) with key K (bytes/string) in AES EBC mode
    AES_obj = AES.new(k, AES.MODE_ECB)
    block_size = len(k)
    padded_x = utils.pkcs7_pad(x, block_size)
    return AES_obj.encrypt(padded_x)

def aes_ebc_decrypt(y, k):
    # decrypt Y (bytes) with key K (bytes/string) in AES EBC mode
    AES_obj = AES.new(k, AES.MODE_ECB)
    return AES_obj.decrypt(y)

def detect_aes_ebc(y, block_size):
    # return True if Y (cipher bytes) encrypted with EBC mode (detects repetition)
    passed_blocks = set()
    repeated_blocks = set()
    for i in range(0, len(y), block_size):
        block = bytes(y[i:i + block_size])
        if block in passed_blocks:
            repeated_blocks.add(block)
        passed_blocks.add(block)
    return len(repeated_blocks) > 0

def aes_cbc_encrypt(x, k, iv):
    # encrypt X (bytes) with key K (plaintext string) and IV (bytes)
    if len(k) != len(iv):
        return utils.int_to_bytes(0)
    block_size = len(k)
    AES_obj = AES.new(k, AES.MODE_ECB)
    padded_x = utils.pkcs7_pad(x, block_size)
    
    cipher_blocks = [iv]
    for i in range(0, len(padded_x), block_size):
        last_cipher_block = cipher_blocks[-1]
        curr_block = padded_x[i:i + block_size]
        xor_block = utils.bytes_xor(last_cipher_block, curr_block)
        next_cipher_block = AES_obj.encrypt(bytes(xor_block))
        cipher_blocks.append(next_cipher_block)
    
    result = bytearray()
    for i in range(1, len(cipher_blocks)):
        result += cipher_blocks[i]
    return result

def aes_cbc_decrypt(y, k, iv):
    # decrypt Y (bytes) with key K (plaintext string) and IV (bytes)
    if len(k) != len(iv):
        return utils.int_to_bytes(0)
    block_size = len(k)
    AES_obj = AES.new(k, AES.MODE_ECB)

    cipher_blocks = [iv] + [y[i:i + block_size] for i in range(0, len(y), block_size)]
    plain_blocks = []
    for i in range(1, len(cipher_blocks)):
        last_cipher_block = cipher_blocks[i - 1]
        curr_cipher_block = cipher_blocks[i]
        decr_curr_block = AES_obj.decrypt(curr_cipher_block)
        xor_block = utils.bytes_xor(last_cipher_block, decr_curr_block)
        plain_blocks.append(xor_block)
    result = bytearray()
    for block in plain_blocks:
        result += block
    return result

#############################
# AES: PADDED ORACLE ATTACK #
#############################

def random_aes_encryption(x, block_size):
    # return random AES encryption (EBC or CBC mode) of X (bytes)
    key = secrets.token_bytes(block_size)
    mode = secrets.randbelow(2)
    pad_count = random.randint(5, 10)
    pad_bytes = secrets.token_bytes(pad_count)
    padded_x = pad_bytes + x + pad_bytes
    if mode == 0:
        iv = secrets.token_bytes(block_size)
        y = aes_cbc_encrypt(padded_x, key, iv)
    else:
        y = aes_ebc_encrypt(padded_x, key)
    return mode, y

def break_random_aes_encryption():
    # (oracle) predict mode of random AES encryption
    block_size = 16
    x = utils.NULL_BYTE * block_size * 4
    actual_mode_num, y = random_aes_encryption(x, block_size)
    actual_mode = actual_mode_num == 1
    predicted_mode = detect_aes_ebc(y, block_size)
    return actual_mode, predicted_mode

def get_padded_oracle_encrypt(unknown):
    # return padded oracle function: AES ECB encrypts input || unknown with constant random key
    block_size = 16
    key = secrets.token_bytes(block_size)
    def padded_oracle_encrypt(x):
        padded_x = x + unknown
        return aes_ebc_encrypt(padded_x, key)
    return padded_oracle_encrypt

def verify_aes_ecb_block_size(unknown):
    # verify that UNKNOWN is encrypted with the std block size 16
    oracle = get_padded_oracle_encrypt(unknown)
    unknown_cipher = oracle(bytes())
    for block_size in range(1, 257):
        inp = utils.NULL_BYTE * block_size
        inp_cipher = oracle(inp)
        inp_cipher_block = inp_cipher[block_size:block_size * 2]
        unknown_cipher_block = unknown_cipher[:block_size]
        if inp_cipher_block == unknown_cipher_block:
            return block_size
    return 0

def break_aes_ecb_encryption(unknown):
    # use padded oracle to indirectly find UNKNOWN with byte-by-byte attack
    block_size = 16
    oracle = get_padded_oracle_encrypt(unknown)
    decrypted = bytearray()
    for block in range(0, len(unknown), block_size):
        for byte in range(block_size):
            if block * block_size + byte >= len(unknown):
                continue
            # get encryption of unknown with null padding
            null_prefix = utils.NULL_BYTE * (block_size - (byte + 1))
            cipher = oracle(null_prefix)
            
            # compare actual cipher block with last unknown byte to 
            # last (block_size - 1) bytes of known padded input
            cipher_block = cipher[block:block + block_size]
            input_test_prefix = (null_prefix + decrypted)[-(block_size - 1):]
            for i in range(256):
                last_test_byte = utils.int_to_bytes(i, 1)
                input_test_block = input_test_prefix + last_test_byte
                cipher_test = oracle(input_test_block)
                cipher_test_block = cipher_test[block:block + block_size]
                if cipher_block == cipher_test_block:
                    decrypted.append(utils.bytes_to_int(last_test_byte))
                    break
    return decrypted




    

