from Crypto.Hash import SHA256 as sha
import random


def get_pub_key(g, p):
    r = random.randint(1, p)
    return pow(g, r) % p, r


def get_s(r, p, pub):
    return pow(pub, r) % p


def get_key(s):
    h = sha.new()
    h.update(bin(s))
    return h.hexdigest()

