from Crypto.Hash import SHA256 as sha
from Crypto.Cipher import AES
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


def encryption(msg, key):
    _AES = AES.new(key, AES.MODE_CBC)
    cipher = _AES.encrypt(msg)
    return cipher


def decryption(cipher, key):
    _AES = AES.new(key, AES.MODE_CBC)
    msg = _AES.decrypt(cipher)
    return msg

