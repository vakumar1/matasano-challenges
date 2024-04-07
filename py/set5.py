import library.public_key as pk
import library.utilities as utils

from Crypto.Util import number
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

def p3():
    msg = utils.ascii_to_bytes("How long, how long will I slide?")

    # attack 1: g = 1 --> A = 1, s = 1
    # attack 2: g = p --> A = 0, s = 0
    for attack_fn in [lambda p: (1, 1, 1), lambda p: (p, 0, 0)]:
        s = pk.DHSenderNegotiated()
        r = pk.DHReceiverNegotiated()
        m = pk.DHMITM_g(attack_fn)
        s.handle_init_msg(r.init_msg2(m.inject_init_msg2_sender(s.init_msg2(r.init_msg(*m.inject_init_msg_sender(*s.init_msg()))))))
        
        sender_data = s.data_msg(msg)
        mitm_data1 = m.decrypt_intercepted_msg(sender_data)
        receiver_data = r.data_msg(sender_data)
        mitm_data2 = m.decrypt_intercepted_msg(receiver_data)
        correct = s.verify_data_msg(receiver_data)

        print(f"MITM DH msg exchange attack: g = {m.g}")
        print("MITM DH msg exchange: verified: ", s.data == msg and correct)
        print("MITM DH msg exchange: attack succeeded: ", mitm_data1 == msg)

    # attack 3: g = p - 1 --> A = 1, s = p - 1 (or 1)
    while True:
        s = pk.DHSenderNegotiated()
        r = pk.DHReceiverNegotiated()
        m = pk.DHMITM_g(lambda p: (p - 1, p - 1, p - 1))
        s.handle_init_msg(r.init_msg2(m.inject_init_msg2_sender(s.init_msg2(r.init_msg(*m.inject_init_msg_sender(*s.init_msg()))))))
        
        # we always guess A = 1 (so the recever has s = 1) --> retry when the sender has s = p - 1
        try:
            sender_data = s.data_msg(msg)
            receiver_data = r.data_msg(sender_data)
            correct = s.verify_data_msg(receiver_data)
        except ValueError:
            correct = False
        if not correct:
            continue

        # try s = 1
        try:
            mitm_data1 = m.decrypt_intercepted_msg(sender_data)
            mitm_data2 = m.decrypt_intercepted_msg(receiver_data)
        except ValueError:
            mitm_data1 = None
            mitm_data2 = None

        # try s = p - 1
        m.s = 1
        try:
            alt_mitm_data1 = m.decrypt_intercepted_msg(sender_data)
            alt_mitm_data2 = m.decrypt_intercepted_msg(receiver_data)
        except ValueError:
            alt_mitm_data1 = None
            alt_mitm_data2 = None


        print(f"MITM DH msg exchange attack: g = {m.p - 1}")
        print("MITM DH msg exchange: verified: ", s.data == msg and correct)
        print("MITM DH msg exchange: attack succeeded: ", mitm_data1 == msg or alt_mitm_data1 == msg)
        return

def p4():
    email = utils.ascii_to_bytes("hash@berkeley.edu")
    password = utils.ascii_to_bytes("fubar123")
    s = pk.SRPServer()
    c = pk.SRPClient(email, password)
    c.recv_params(*s.send_params())
    s.recv_new_email(*c.send_new_email())
    c.handle_auth_init(*s.recv_auth_init(*c.send_auth_init()))
    valid = s.recv_auth_req(*c.send_auth_req())
    print("SRP Protocol: valid auth request: ", valid)

def p5():
    email = utils.ascii_to_bytes("hash@berkeley.edu")
    password = utils.ascii_to_bytes("fubar123")
    s = pk.SRPServer()
    c = pk.SRPClient(email, password)
    c.recv_params(*s.send_params())
    s.recv_new_email(*c.send_new_email())

    m = pk.MaliciousSRPClient(s.p, s.g, s.k)
    m.handle_auth_init(*s.recv_auth_init(*m.send_auth_init(email)))
    valid = s.recv_auth_req(*m.send_auth_req())
    print("SRP with A=0: valid auth request: ", valid)

def p6():
    # test simple SRP works with valid server + client
    email = utils.ascii_to_bytes("hash@berkeley.edu")
    password = utils.int_to_bytes(42, 8)
    s = pk.SimpleSRPServer()
    c = pk.SimpleSRPClient(email, password)
    c.recv_params(*s.send_params())
    s.recv_new_email(*c.send_new_email())
    c.handle_auth_init(*s.recv_auth_init(*c.send_auth_init()))
    valid = s.recv_auth_req(*c.send_auth_req())
    print("Simpler SRP Protocol: valid auth request=", valid)

    # use MITM + dictionary attack to get user password
    s = pk.SimpleSRPServer()
    c = pk.SimpleSRPClient(email, password)
    c.recv_params(*s.send_params())
    s.recv_new_email(*c.send_new_email())

    m = pk.MITMSimpleSRPServer(s.p, s.g)
    c.handle_auth_init(*m.recv_auth_init(*c.send_auth_init()))
    password = m.recv_auth_req(*c.send_auth_req())
    print("Simpler SRP Protocol MITM + dictionary attack: password=", utils.bytes_to_int(password))

def p7():
    # test mult inverse
    p1 = number.getPrime(1024)
    p2 = number.getPrime(1024)
    p1, p2 = max(p1, p2), min(p1, p2)
    i = pk.egcd(p1, p2)
    print(f"Mult inverse successful: {(p1 * i) % p2 == 1}")

    # test RSA encrypt/decrypt
    m = utils.bytes_to_int(utils.ascii_to_bytes("This is the message."))
    rsa_bits, public_key, private_key = pk.rsa_gen_params()
    c = pk.rsa_encrypt(m, public_key)
    m_d = pk.rsa_decrypt(c, private_key)
    print(f"Decryption successful: {m == m_d}")

def p8():
    m = utils.bytes_to_int(utils.ascii_to_bytes("This is the message."))
    rsa_bits, public_key0, _ = pk.rsa_gen_params()
    c0 = pk.rsa_encrypt(m, public_key0)
    rsa_bits, public_key1, _ = pk.rsa_gen_params()
    c1 = pk.rsa_encrypt(m, public_key1)
    rsa_bits, public_key2, _ = pk.rsa_gen_params()
    c2 = pk.rsa_encrypt(m, public_key2)
    m_d_3 = pk.break_rsa_crt([c0, c1, c2], [public_key0, public_key1, public_key2])
    print(f"CRT break successful: {m ** 3 == m_d_3}")

def main():
    functions = {
        "1": p1,
        "2": p2,
        "3": p3,
        "4": p4,
        "5": p5,
        "6": p6,
        "7": p7,
        "8": p8,
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
    