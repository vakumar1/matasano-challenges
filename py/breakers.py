from conversions import IntRep

class SingleByteXOR:
    char_freqs = {
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
    def __init__(self, base, chunk_size):
        # base: used for string rep (e.g. hex -> 16)
        # chunk_size: used for string rep with base (e.g. byte hex -> 2)
        self.base = base
        self.chunk_size = chunk_size

    def encrypt(self, x: IntRep, k: IntRep):
        # encrypt PT X with single byte key K
        x_len = len(x.get_string(self.base))
        while x_len % self.chunk_size != 0:
            x_len += 1
        k_ext = k.extend(self.base, self.chunk_size, x_len)
        y = IntRep(x.get_int() ^ k_ext.get_int())
        return y

    def decrypt(self, y: IntRep, k: IntRep):
        # decrypt CT Y with single byte key K
        y_len = len(y.get_string(self.base))
        while y_len % self.chunk_size != 0:
            y_len += 1
        k_ext = k.extend(self.base, self.chunk_size, y_len)
        x = IntRep(y.get_int() ^ k_ext.get_int())
        return x

    def break_enc(self, y: IntRep):
        # return best single byte key
        best_prob = 0.0
        best_key = IntRep()
        for i in range(self.base ** self.chunk_size):
            k = IntRep(i)
            x = self.decrypt(y, k)
            prob = self.str_prob(x)
            if prob > best_prob:
                best_prob = prob
                best_key = k
        return best_key

    def str_prob(self, x: IntRep):
        # get the probability of PT X
        eng_str = x.get_ascii()
        score = 0.0
        for c in eng_str:
            try:
                score += self.char_freqs[c.lower()]
            except KeyError:
                score += 0
        if len(eng_str) == 0:
            return score
        else:
            return score / len(eng_str)

class RepeatingKeyXOR:
    def __init__(self, base, chunk_size):
        # base: used for string rep (e.g. hex -> 16)
        # chunk_size: used for string rep with base (e.g. byte hex -> 2)
        self.base = base
        self.chunk_size = chunk_size

    def encrypt(self, x: IntRep, k: IntRep):
        # encrypt PT X with repeating key K
        k_ext = k.extend(self.base, len(k.get_string(self.base)), len(x.get_string(self.base)))
        y = IntRep(x.get_int() ^ k_ext.get_int())
        return y

    def decrypt(self, y: IntRep, k: IntRep):
        # decrypt CT Y with repeating key K
        k_ext = k.extend(self.base, len(k.get_string(self.base)), len(y.get_string(self.base)))
        x = IntRep(y.get_int() ^ k_ext.get_int())
        return x

    def break_enc(self, y: IntRep):
        # return the best repeating key
        key_size = self.get_key_size(y, 2, 40, 10)
        y_str = y.get_string(self.base)

        # split y's string rep into key_size blocks
        block_strs = ["" for _ in range(key_size)]
        for i in range(0, len(y_str), self.chunk_size):
            block_strs[(i // self.chunk_size) % key_size] += y_str[i:i + self.chunk_size]

        # for each block, find the best single byte key and append to key
        SBX = SingleByteXOR(self.base, self.chunk_size)
        key = ""
        for b_str in block_strs:
            b = IntRep(b_str, self.base)
            b_key = SBX.break_enc(b)
            b_key_str = b_key.get_string(self.base)
            while len(b_key_str) < self.chunk_size:
                b_key_str = "0" + b_key_str
            key += b_key_str
        return IntRep(key, self.base)

    def get_key_size(self, y: IntRep, start, end, num_blocks):
        # return the best key_size for CT Y
        # start: min key size
        # end: max key size
        # num blocks: how many blocks of CT Y to compare
        y_str = y.get_string(self.base)
        best_dist = float("inf")
        best_size = 0
        end = min(end, (len(y_str) / (self.chunk_size * num_blocks) - 1))
        for size in range(start, end):
            blocks = []
            for i in range(num_blocks):
                block = y_str[i * (size * self.chunk_size):(i + 1) * (size * self.chunk_size)]
                blocks.append(IntRep(block, self.base))

            dist = 0.0
            for i in range(num_blocks):
                for j in range(i):
                    dist += self.hamming_dist(blocks[i], blocks[j])

            norm_dist = dist / size
            if norm_dist < best_dist:
                best_dist = norm_dist
                best_size = size
        return best_size

    def hamming_dist(self, s1: IntRep, s2: IntRep):
        # find hamming distance between two ints
        bit_diff = IntRep(s1.get_int() ^ s2.get_int()).get_string(2)
        dist = 0
        for c in bit_diff:
            if c != "0":
                dist += 1
        return dist
