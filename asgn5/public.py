from Crypto.Hash import SHA256 as sha
from Crypto.Cipher import AES
import random
import math
import os
from Crypto.Util import number
n_length = 50
C_SIZE = 16


def gcd(p,q):
    while q != 0:
        p, q = q, p%q
    return p


def is_coprime(x, y):
    return gcd(x, y) == 1


def add_padding(text):
    pad_len = C_SIZE - (len(text) % C_SIZE)
    text += bytes([pad_len]) * pad_len
    return text


def get_pub_key(g, p):
    r = random.randint(1, p)
    return pow(g, r, p), r


def get_s(r, p, pub):
    return pow(pub, r, p)


def get_key(s):
    h = sha.new()
    h.update(str(s).encode())
    return h.digest()[:16]  # binary


def encryption(msg, key, iv):
    _AES = AES.new(key, AES.MODE_CBC, IV=iv)
    cipher = _AES.encrypt(msg)
    return cipher


def decryption(cipher, key, iv):
    _AES = AES.new(key, AES.MODE_CBC, IV=iv)
    msg = _AES.decrypt(cipher)
    return msg


def rsa_encryt(msg, e, n):
    return pow(msg, e, n)


def rsa_decrypt(cipher, d, n):
    return pow(cipher, d, n)


def solve_linear_congruence(a, b, m):
    """ https://stackoverflow.com/questions/63021828/solving-modular-linear-congruences-for-large-numbers"""
    """ Describe all solutions to ax = b  (mod m), or raise ValueError. """
    g = math.gcd(a, m)
    if b % g:
        raise ValueError("No solutions")
    a, b, m = a//g, b//g, m//g
    return pow(a, -1, m) * b % m


def rsa(msg):
    e = 65537
    p = number.getPrime(n_length)
    q = number.getPrime(n_length)
    n = p * q
    phi = (p - 1) * (q - 1)
    m = b"hi bob".hex()
    m_int = int(m, 16)
    # print(is_coprime(phi, e))  # True
    d = solve_linear_congruence(e, 1, phi)
    cipher = rsa_encryt(m_int, e, n)
    msg_int = rsa_decrypt(cipher, d, n)
    msg = bytes.fromhex(hex(msg_int)[2:])
    print(msg)


def task1():
    p = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 " \
        "13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 " \
        "A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371 "
    p = int(p.replace(" ", ""), 16)
    g = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 " \
        "160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A " \
        "D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5 "
    g = int(g.replace(" ", ""), 16)
    m1 = b"Hi Bob!"
    m2 = b"Hi Alice!"
    IV = os.urandom(C_SIZE)
    pub1, a = get_pub_key(g, p)  # pub1 = A
    pub2, b = get_pub_key(g, p)  # pub2 = B
    s1 = get_s(a, p, pub2)
    s2 = get_s(b, p, pub1)
    k1 = get_key(s1)
    k2 = get_key(s2)
    print(k1 == k2)  # check if shared keys are the same"
    c1 = encryption(add_padding(m1), k1, IV)
    print(decryption(c1, k2, IV))


def task2_attack1():
    p = 37
    g = 5
    m1 = b"Hi Bob!"
    m2 = b"Hi Alice!"
    IV = os.urandom(C_SIZE)
    pub1, a = get_pub_key(g, p)  # pub1 = A
    pub2, b = get_pub_key(g, p)  # pub2 = B
    s1 = get_s(a, p, p)
    s2 = get_s(b, p, p)
    k1 = get_key(s1)
    k2 = get_key(s2)
    c1 = encryption(add_padding(m1), k1, IV)
    print(decryption(c1, get_key(0), IV))


def task2_attack2():
    p = 37
    g = p-1
    m1 = b"Hi Bob!"
    m2 = b"Hi Alice!"
    IV = os.urandom(C_SIZE)
    pub1, a = get_pub_key(g, p)  # pub1 = A
    pub2, b = get_pub_key(g, p)  # pub2 = B
    s1 = get_s(a, p, pub2)
    s2 = get_s(b, p, pub1)
    k1 = get_key(s1)
    k2 = get_key(s2)
    c1 = encryption(add_padding(m1), k1, IV)
    # print(decryption(c1, get_key(1), IV))  # g = 1
    # print(decryption(c1, get_key(0), IV))  # g = p
    print(decryption(c1, get_key(1), IV))  # g = p - 1


if __name__ == "__main__":
    rsa("hello")
