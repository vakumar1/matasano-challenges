import library.public_key as pk

import sys

def p1():
    p, g = 37, 5
    A, B, a, b = pk.diffie_hellman_gen_keys(g, p)
    keys1 = pk.diffie_hellman_gen_secret(g, p, a, B)
    keys2 = pk.diffie_hellman_gen_secret(g, p, b, A)
    print("Simple DH key exchange: ", keys1 == keys2)

    p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    A, B, a, b = pk.diffie_hellman_gen_keys(g, p)
    keys1 = pk.diffie_hellman_gen_secret(g, p, a, B)
    keys2 = pk.diffie_hellman_gen_secret(g, p, b, A)
    print("Larger DH key exchange: ", keys1 == keys2)

def main():
    functions = {
        "1": p1
    }

    if len(sys.argv) < 2:
        execute = functions.keys()
    else:
        execute = sys.argv[1:]
    for func in execute:
        if func not in functions:
            continue
        print(f"================================= {func} =================================")
        functions[func]()

if __name__ == "__main__":
    main()
    