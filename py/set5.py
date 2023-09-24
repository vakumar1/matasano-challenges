import library.public_key as pk
import library.utilities as utils

import sys

def p1():
    p, g = 37, 5
    a, A = pk.diffie_hellman_gen_keys(g, p)
    b, B = pk.diffie_hellman_gen_keys(g, p)
    keys1 = pk.diffie_hellman_gen_secret(g, p, a, B, pk.sha256_keymac_hash_fn)
    keys2 = pk.diffie_hellman_gen_secret(g, p, b, A, pk.sha256_keymac_hash_fn)
    print("Simple DH key exchange: ", keys1 == keys2)

    p = pk.DEF_P
    g = pk.DEF_G
    a, A = pk.diffie_hellman_gen_keys(g, p)
    b, B = pk.diffie_hellman_gen_keys(g, p)
    keys1 = pk.diffie_hellman_gen_secret(g, p, a, B, pk.sha256_keymac_hash_fn)
    keys2 = pk.diffie_hellman_gen_secret(g, p, b, A, pk.sha256_keymac_hash_fn)
    print("Larger DH key exchange: ", keys1 == keys2)

def p2():
    # verify protocol is correct
    sender = pk.DHSender()
    receiver = pk.DHReceiver()
    sender.handle_init_msg(receiver.init_msg(*sender.init_msg()))

    msg = utils.ascii_to_bytes("How long, how long will I slide?")
    correct = sender.verify_data_msg(receiver.data_msg(sender.data_msg(msg)))
    print("DH msg exchange: ", sender.data == msg and correct)

    # test MITM attack
    sender = pk.DHSender()
    receiver = pk.DHReceiver()
    mitm = pk.DHMITM()
    sender.handle_init_msg(mitm.inject_init_msg_receiver(receiver.init_msg(*mitm.inject_init_msg_sender(*sender.init_msg()))))

    sender_data = sender.data_msg(msg)
    mitm_data1 = mitm.decrypt_intercepted_msg(sender_data)
    receiver_data = receiver.data_msg(sender_data)
    mitm_data2 = mitm.decrypt_intercepted_msg(receiver_data)
    correct = sender.verify_data_msg(receiver_data)

    print("MITM DH msg exchange: verified: ", sender.data == msg and correct)
    print("MITM DH msg exchange: attack succeeded: ", mitm_data1 == msg)


def main():
    functions = {
        "1": p1,
        "2": p2
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
    