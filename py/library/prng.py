import time
import random
import library.utilities as utils 

###########################################
# Mersenne Twister PRNG and Stream Cipher #
###########################################

class MT:
    # MT19937 constants
    w = 32
    n = 624
    m = 397
    r = 31
    
    # seeding coefficient
    f = 1812433253
    
    # tempering bit masks/shifts
    b = 0x9D2C5680
    c = 0xEFC60000
    s = 7
    t = 15
    u = 11
    d = 0xFFFFFFFF
    l = 18

    # twisting parameters
    a = 0x9908B0DF
    lower_mask = (1 << r) - 1
    upper_mask = (~lower_mask) % (1 << 32)

    # initialize MTwister's internal state (624 int array)
    def __init__(self, seed):
        self.state = [0 for _ in range(MT.n)]
        self.index = MT.n
        self.state[0] = seed
        for i in range(1, MT.n):
            self.state[i] = (MT.f * (self.state[i - 1] ^ (self.state[i - 1] >> (MT.w - 2))) + i) % (1 << 32)

    def set_state(self, state):
        self.state = state
    
    # get next random number from state and temper
    def extract_number(self):
        if self.index >= MT.n:
            self.twist()
        y = self.state[self.index] 
        y = y ^ ((y >> MT.u) & MT.d) 
        y = y ^ ((y << MT.s) & MT.b)
        y = y ^ ((y << MT.t) & MT.c) 
        y = y ^ (y >> MT.l)
        self.index += 1
        return y % (1 << 32)

    # "twist" the state using the twister matrix
    def twist(self):
        for i in range(MT.n):
            x = (self.state[i] & MT.upper_mask) + (self.state[(i + 1) % MT.n] & MT.lower_mask)
            xA = x >> 1
            if x % 2 == 1:
                xA = xA ^ MT.a

            self.state[i] = self.state[(i + MT.m) % MT.n] ^ xA
        self.index = 0

class MTCipher:
    def __init__(self, seed):
        self.PRNG = MT(seed)
        self.ciphers = bytearray()

    def regenerate(self):
        next_num = self.PRNG.extract_number()
        next_num_bytes =  utils.int_to_bytes(next_num, 4)
        self.ciphers += next_num_bytes        

    def get_key(self, n_bytes):
        while len(self.ciphers) <= n_bytes:
            self.regenerate()

        key = self.ciphers[:n_bytes]
        self.cipher = self.ciphers[n_bytes:]
        return key


######################
# CRACK MT19937 SEED #
######################

def randomly_seeded_prng_first_number():
    seed = (int(time.time()) - random.randint(40, 100) - random.randint(40, 100)) % (1 << 32)
    generator = MT(seed)
    return generator.extract_number(), seed

def get_seed_from_first_number(first_number):
    current_time = int(time.time())
    for i in range(current_time - 300, current_time):
        generator = MT(i)
        if generator.extract_number() == first_number:
            return i
    return -1


def crack_mt_seed():
    first_number, seed = randomly_seeded_prng_first_number()
    predicted_seed = get_seed_from_first_number(first_number)
    return seed == predicted_seed

########################
# CLONE MT19937 OBJECT #
########################

def zero_pad(bit_string):
    if len(bit_string) > MT.w:
        return bit_string
    return '0' * (MT.w - len(bit_string)) + bit_string

def untemper_state_value(state_value):
    y4 = bin(state_value)[2:]
    y4 = zero_pad(y4)
    y3 = y4[:MT.l]
    for i in range(MT.l, MT.w):
        y4_bit = y4[i]
        y3_bit = y3[i - MT.l]
        next_bit = '0' if y3_bit == y4_bit else '1'
        y3 += next_bit

    c = bin(MT.c)[2:]
    c = zero_pad(c)
    y2 = y3[-MT.t:]
    for i in range(MT.w - MT.t - 1, -1, -1):
        y3_bit = y3[i]
        c_bit = c[i]
        y2_bit = '0' if c_bit == '0' else y2[MT.t - 1]
        next_bit = '0' if y2_bit == y3_bit else '1'
        y2 = next_bit + y2


    b = bin(MT.b)[2:]
    b = zero_pad(b)
    y1 = y2[-MT.s:]
    for i in range(MT.w - MT.s - 1, -1, -1):
        y2_bit = y2[i]
        b_bit = b[i]
        # print(len(y1), MT.s - 1)
        y1_bit = '0' if b_bit == '0' else y1[MT.s - 1]
        next_bit = '0' if y1_bit == y2_bit else '1'
        y1 = next_bit + y1

    d = bin(MT.d)[2:]
    d = zero_pad(d)
    y0 = y1[:MT.u]
    for i in range(MT.u, MT.w):
        y1_bit = y1[i]
        d_bit = d[i]
        y0_bit = '0' if d_bit == '0' else y0[i - MT.u]
        next_bit = '0' if y0_bit == y1_bit else '1'
        y0 += next_bit
    return int(y0, 2)

def clone_mt(MTwister: MT):
    new_state = []
    for i in range(MT.n):
        tempered = MTwister.extract_number()
        untempered = untemper_state_value(tempered)
        new_state.append(untempered)
    
    MTwisterClone = MT(41)
    MTwisterClone.set_state(new_state)
    return MTwisterClone

#########################
# MT19937 STREAM CIPHER #
#########################

def pad_and_encrypt(cipher: MTCipher, x):
    pad_size = random.randint(0, 10)
    pad = bytearray()
    for _ in range(pad_size):
        pad +=  utils.int_to_bytes(random.randint(0, 255), 1)
    padded_x = pad + x
    k = cipher.get_key(len(padded_x))
    y =  utils.bytes_xor(padded_x, k)
    return y

def recover_seed_from_padded_encryption(x, y):
    pad_size = len(y) - len(x)
    start_byte = pad_size
    x_start = 0
    if start_byte % 4 != 0:
        new_start_byte = (start_byte // 4 * 4) + 4
        x_start = new_start_byte - start_byte
        start_byte = new_start_byte
    index = start_byte // 4
    state =  utils.bytes_xor(x[x_start:x_start + 4], y[start_byte:start_byte + 4])
    for seed in range(1 << 16):
        cipher = MTCipher(seed)
        last_state = cipher.get_key((index + 1) * 4)[-4:]
        if last_state == state:
            return seed
