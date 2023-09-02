import library.utilities as utils
import library.xor as xor
from Crypto.Cipher import AES
import secrets
import random


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
    # WARNING: returns PADDED plaintext (PKCS7 padding needs to be removed manually)
    if len(k) != len(iv):
        return utils.int_to_bytes(0)
    block_size = len(k)
    AES_obj = AES.new(k, AES.MODE_ECB)

    cipher_blocks = [iv] + [y[i:i + block_size] for i in range(0, len(y), block_size)]
    plain_blocks = []
    for i in range(1, len(cipher_blocks)):
        last_cipher_block = cipher_blocks[i - 1]
        curr_cipher_block = cipher_blocks[i]
        decr_curr_block = AES_obj.decrypt(bytes(curr_cipher_block))
        xor_block = utils.bytes_xor(last_cipher_block, decr_curr_block)
        plain_blocks.append(xor_block)
    padded = bytearray()
    for block in plain_blocks:
        padded += block
    return padded

############################
# AES: DETECT ECB/CBC MODE #
############################

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

###########################################
# AES: DETERMINISTIC PADDED ORACLE ATTACK #
###########################################

def get_padded_oracle_encrypt(unknown):
    # return padded oracle function: AES ECB encrypts (input || unknown) with constant random key
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
            if block + byte >= len(unknown):
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
                cipher_test_block = cipher_test[:block_size]
                if cipher_block == cipher_test_block:
                    decrypted.append(utils.bytes_to_int(last_test_byte))
                    break
    return decrypted

####################################
# AES: RANDOM PADDED ORACLE ATTACK #
####################################

def get_random_padded_oracle_encrypt(unknown):
    # return padded oracle function: AES ECB encrypts (rand_padding || input || unknown) 
    # with constant random key
    block_size = 16
    key = secrets.token_bytes(block_size)
    pad_count = random.randint(0, block_size - 1)
    pad_bytes = secrets.token_bytes(pad_count)
    def padded_oracle_encrypt(x):
        padded_x = pad_bytes + x + unknown
        return aes_ebc_encrypt(padded_x, key)
    return padded_oracle_encrypt

def get_random_padding_size(oracle):
    block_size = 16
    null_block = utils.NULL_BYTE * block_size
    null_block_cipher = oracle(null_block * 2)[block_size:block_size * 2]
    for suffix in range(1, block_size + 1):
        null_block_ext = null_block + utils.NULL_BYTE * suffix
        null_block_ext_cipher = oracle(null_block_ext)[block_size:block_size * 2]
        if null_block_ext_cipher == null_block_cipher:
            return block_size - suffix
    return 0

def break_aes_ecb_random_encryption(unknown):
    block_size = 16
    oracle = get_random_padded_oracle_encrypt(unknown)
    prepad_size = get_random_padding_size(oracle)
    end_pad_null_block = utils.NULL_BYTE * (block_size - prepad_size)
    decrypted = bytearray()
    for block in range(0, len(unknown), block_size):
        for byte in range(block_size):
            if block + byte >= len(unknown):
                continue
            
            # get encryption of unknown with null padding
            null_prefix = utils.NULL_BYTE * (block_size - (byte + 1))
            cipher = oracle(end_pad_null_block + null_prefix)
            
            # compare actual cipher block with last unknown byte to 
            # last (block_size - 1) bytes of known padded input
            cipher_block = cipher[block + block_size:block + block_size * 2]
            input_test_prefix = (null_prefix + decrypted)[-(block_size - 1):]
            for i in range(256):
                last_test_byte = utils.int_to_bytes(i, 1)
                input_test_block = input_test_prefix + last_test_byte
                cipher_test = oracle(end_pad_null_block + input_test_block)
                cipher_test_block = cipher_test[block_size:block_size * 2]
                if cipher_block == cipher_test_block:
                    decrypted.append(utils.bytes_to_int(last_test_byte))
                    break
    return decrypted

####################
# AES: ROLE ATTACK #
####################

def encrypt_encoded_profile(email, key):
    encoded_profile_string = utils.generate_profile(email)
    encoded_profile_bytes = utils.ascii_to_bytes(encoded_profile_string)
    encrypted_profile = aes_ebc_encrypt(encoded_profile_bytes, key)
    return encrypted_profile

def break_aes_user_role():
    block_size = 16
    key = secrets.token_bytes(block_size)
    
    # get cipher prefix (profile without role)
    email13 = "x" * 13
    cipher_prefix = encrypt_encoded_profile(email13, key)[:block_size * 2]

    # get cipher stub (only profile role with padding)
    padded_admin = utils.pkcs7_pad(utils.ascii_to_bytes("admin"), block_size)
    email10 = "x" * 10 + utils.bytes_to_ascii(padded_admin)
    cipher_stub = encrypt_encoded_profile(email10, key)[block_size:block_size * 2]

    cipher = cipher_prefix + cipher_stub
    encoded_profile = aes_ebc_decrypt(cipher, key)
    return encoded_profile

#################################
# AES: CBC BIT-FLIP ROLE ATTACK #
#################################

def encrypt_user_data(data, key, iv):
    encoded_data_string = utils.generate_user_data(data)
    encoded_data_bytes = utils.ascii_to_bytes(encoded_data_string)
    encrypted_data = aes_cbc_encrypt(encoded_data_bytes, key, iv)
    return encrypted_data

def user_has_admin_permissions(encr_data, key, iv):
    decrypted_data_bytes = aes_cbc_decrypt(encr_data, key, iv)
    data_string = utils.bytes_to_ascii(decrypted_data_bytes)
    permission = ";admin=true;" in data_string
    return decrypted_data_bytes, permission

def break_aes_cbc_user_data():
    block_size = 16
    key = secrets.token_bytes(block_size)
    iv = secrets.token_bytes(block_size)

    valid_inp_data = "XXXXXSadminEtrue"
    encr_inp_data = encrypt_user_data(valid_inp_data, key, iv)
    for i in range(256):
        for j in range(256):
            encr_inp_data[21] = i
            encr_inp_data[27] = j
            data, permission = user_has_admin_permissions(encr_inp_data, key, iv)
            if permission:
                return data
    return None
    
########################################
# AES: CBC PADDED RANDOM ORACLE ATTACK #
########################################

def get_random_cbc_oracle_and_pad_verifier(unknowns):
    # return encryption oracle and padding verifier functions
    block_size = 16
    key = secrets.token_bytes(block_size)
    iv = secrets.token_bytes(block_size)
    
    def random_oracle_encrypt():
        plain = random.choice(unknowns)
        return aes_cbc_encrypt(plain, key, iv), iv
    
    def verify_pkcs7_padding(cipher, user_iv):
        padded = aes_cbc_decrypt(cipher, key, user_iv)
        try:
            _ = utils.remove_pkcs7_pad(padded, block_size)
            return True
        except ValueError:
            return False
    return random_oracle_encrypt, verify_pkcs7_padding

def decrypt_cipher_with_padding_attack(cipher, iv, verifier):
    # return decryption of CIPHER using padding verifier attack
    block_size = 16
    cipher_blocks = [iv] + [cipher[i:i + block_size] for i in range(0, len(cipher), block_size)]
    decrypted = bytearray()
    for block in range(1, len(cipher_blocks)):
        decrypted_block = bytearray(block_size)
        pre_block_mask = bytearray(block_size * 2)
        sub_cipher = bytearray()
        for sub_block in range(block + 1):
            sub_cipher += cipher_blocks[sub_block]
        for byte in range(block_size - 1, -1, -1):
            valid_pad_byte_value = block_size - byte
            for post_byte in range(block_size - 1, byte, -1):
                pre_block_mask[post_byte] = decrypted_block[post_byte] ^ valid_pad_byte_value
            start = 0
            if block == len(cipher_blocks) - 1 and byte == block_size - 1:
                start = 1
            for mask_byte in range(start, 256):
                pre_block_mask[byte] = mask_byte
                masked_cipher = utils.bytes_xor(sub_cipher, pre_block_mask)
                if verifier(masked_cipher[block_size:], masked_cipher[:block_size]):
                    decrypted_block[byte] = valid_pad_byte_value ^ mask_byte
                    break
        decrypted += decrypted_block
    return decrypted
             
def break_random_cbc_oracle(unknowns):
    # break CBC encryption for random UNKNOWNS with padding verifier attack
    oracle, verifier = get_random_cbc_oracle_and_pad_verifier(unknowns)
    decrypted = []
    while len(decrypted) < 10:
        cipher, iv = oracle()
        plain = decrypt_cipher_with_padding_attack(cipher, iv, verifier)
        if plain not in decrypted:
            decrypted.append(plain)
    return decrypted

###############################
# AES CBC MODE: IV=KEY ATTACK #
###############################

def break_aes_cbc_keyiv_user_data():
    block_size = 16
    key = secrets.token_bytes(block_size)
    iv = key

    valid_inp_data = "A" * (3 * block_size)
    encr_inp_data = encrypt_user_data(valid_inp_data, key, iv)
    encr_blocks = [encr_inp_data[:block_size], 
                encr_inp_data[block_size:2 * block_size], 
                encr_inp_data[2 * block_size:3 * block_size]]
    encr_inp_data_mod = encr_blocks[0] + utils.NULL_BYTE * block_size + encr_blocks[0]
    decrypted_data_bytes, permission = user_has_admin_permissions(encr_inp_data_mod, key, iv)
    decr_blocks = [decrypted_data_bytes[:block_size],
                decrypted_data_bytes[block_size:2 * block_size],
                decrypted_data_bytes[2 * block_size:3 * block_size]]
    key_prime = utils.bytes_xor(decr_blocks[0], decr_blocks[2])
    return key == key_prime

############################################
# AES CTR MODE: BASE ENCRYPTION/DECRYPTION #
############################################

def aes_little_endian_ctr_encr_decr(inp, key, nonce):
    nonce_size = 8
    block_size = 16
    inp_blocks = [inp[i:min(i + block_size, len(inp))] 
        for i in range(0, len(inp), block_size)]
    AES_obj = AES.new(key, AES.MODE_ECB)
    
    out_blocks = []
    for ctr, inp_block in enumerate(inp_blocks):
        nonce_block = nonce + utils.int_to_bytes_little_end(ctr, nonce_size)
        keystream_block = AES_obj.encrypt(bytes(nonce_block))[:len(inp_block)]
        out_block = utils.bytes_xor(inp_block, keystream_block)
        out_blocks.append(out_block)
    
    out = bytearray()
    for block in out_blocks:
        out += block
    return out

##########################################
# AES CTR MODE: BREAK REPEATED KEYSTREAM #
##########################################

def break_aes_ctr_encr(inps):
    shortest_len = min([len(inp) for inp in inps])
    rk_inp = bytearray()

    for inp in inps:
        rk_inp += inp[:shortest_len]
    
    rk_key = xor.rk_xor_break(rk_inp, shortest_len)
    decr_rk_inp = xor.rk_xor_decrypt(rk_inp, rk_key)
    decr_inps = [decr_rk_inp[i:i + shortest_len] 
                for i in range(0, len(decr_rk_inp), shortest_len)]
    return decr_inps

######################
# AES CTR MODE: SEEK #
######################

def aes_little_endian_ctr_random_encr(inp, nonce):
    block_size = 16
    nonce_size = 8
    key = secrets.token_bytes(block_size)
    encr = aes_little_endian_ctr_encr_decr(inp, key, nonce)

    def edit(ciphertext, offset, newtext):
        AES_obj = AES.new(key, AES.MODE_ECB)
        start_index = (offset // block_size)
        end_index = ((offset + len(newtext)) // block_size) + 1
        keystream = bytearray()
        for ctr in range(start_index, end_index):
            nonce_block = nonce + utils.int_to_bytes_little_end(ctr, nonce_size)
            keystream_block = AES_obj.encrypt(bytes(nonce_block))
            keystream += keystream_block
        key_start = offset % 16
        key_end = key_start + len(newtext)
        new_ciphertext = ciphertext[:]
        new_ciphertext[offset:offset + len(newtext)] = utils.bytes_xor(newtext, keystream[key_start:key_end])
        return new_ciphertext
    
    return encr, edit

def break_aes_ctr_random_encr(encr, edit):
    return edit(encr, 0, encr)


#####################################
# AES CTR MODE: BITFLIP ROLE ATTACK #
#####################################

def encrypt_user_data_ctr(data, key, iv):
    encoded_data_string = utils.generate_user_data(data)
    encoded_data_bytes = utils.ascii_to_bytes(encoded_data_string)
    encrypted_data = aes_little_endian_ctr_encr_decr(encoded_data_bytes, key, iv)
    return encrypted_data

def user_has_admin_permissions_ctr(encr_data, key, iv):
    decrypted_data_bytes = aes_little_endian_ctr_encr_decr(encr_data, key, iv)
    data_string = utils.bytes_to_ascii(decrypted_data_bytes)
    permission = ";admin=true;" in data_string
    return decrypted_data_bytes, permission

def break_aes_ctr_user_data():
    block_size = 16
    nonce_size = 8
    key = secrets.token_bytes(block_size)
    nonce = secrets.token_bytes(nonce_size)

    valid_inp_data = "XXXXXSadminEtrue"
    encr_inp_data = encrypt_user_data_ctr(valid_inp_data, key, nonce)
    for i in range(256):
        for j in range(256):
            encr_inp_data[37] = i
            encr_inp_data[43] = j
            data, permission = user_has_admin_permissions_ctr(encr_inp_data, key, nonce)
            if permission:
                return data
    return None

