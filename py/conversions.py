import base64
from binascii import hexlify, unhexlify

class IntRep:
    base_dicts = {
        2: "01",
        10: "0123456789",
        16: "0123456789abcdef",
        64: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    }

    def __init__(self, val=0, base=0, ascii=False):
        # cache will store string reps
        self.str_cache = {}
        
        # convert ascii to hex and store int
        if ascii:
            h = hexlify(val.encode()).decode()
            self.str_cache[16] = h
            self.num = int(h, 16)
        
        # encode integer val as base 0
        elif base == 0:
            self.num = val

        # compatible with base 2, 10, 16, 64
        elif base in self.base_dicts:
            if base <= 32:
                self.num = int(val, base)
            elif base == 64:
                self.str_cache[16] = base64.b64decode(val).hex()
                self.num = int(self.str_cache[16], 16)
            self.str_cache[base] = val

    def get_int(self):
        return self.num
    
    def get_string(self, base):
        # no calculation required: 0 or stored in cache
        if self.num == 0:
            return "0"
        if base in self.str_cache:
            return self.str_cache[base]

        # special base cases: 2, 16
        if base == 2:
            self.str_cache[base] = (bin(self.num)[2:])
            return self.str_cache[base]
        if base == 16:
            self.str_cache[base] = (hex(self.num)[2:])
            return self.str_cache[base]
       
        # manually find base rep (SLOW !!!)
        else:
            num_str = ""
            base_dict = self.base_dicts[base]
            curr = self.num
            while curr > 0:
                digit = base_dict[curr % base]
                curr = curr // base
                num_str = digit + num_str
            self.str_cache[base] = num_str
            return num_str

    def get_bytes(self):
        return unhexlify(self.get_string(16))

    def get_ascii(self):
        # get ASCII rep: returns empty string if error
        h = self.get_string(16)
        if len(h) % 2 == 1:
            h = "0" + h
        try:
            return bytes.fromhex(h).decode("ASCII")
        except UnicodeDecodeError:
            return ""

    def extend(self, base, chunk_size, length):
        # zero-extend NUM to have CHUNK_SIZE length
        chunk_str = self.get_string(base)
        while len(chunk_str) < chunk_size:
            chunk_str = "0" + chunk_str

        # copy zero-extended NUM until it has LENGTH length
        ext_str = ""
        for i in range(length):
            ext_str += chunk_str[i % chunk_size]
        return IntRep(ext_str, base)


    
