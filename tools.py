#from Crypto.Cipher import AES
import string
import random


def checkDecryption(str1, str2):
    isCorrect = False
    if(str1 == str2):
        isCorrect = True
    print("Valid Decryption: ", isCorrect)


def random_bytes(size: int):
    return open("/dev/urandom", "rb").read(size)


def xor_bytes(str1, str2):
    return bytes(a ^ b for a, b in zip(str1, str2))


def xor_otp(key: bytes, text: bytes):

    if(len(key) == len(text)):
        encrypted = xor_bytes(key, text)
    else:
        raise Exception("Key and text are not the same size!")

    return encrypted


# def AES():
#    key = '1F61ECB5ED5D6BAF8D7A7068B28DCC8E'
#    IV = 16 * '\x00'
#    mode = AES.MODE_CBC
#    encryptor = AES.new(key, mode, IV=IV)
#    text = '020ABC00ABCDEFf8d500000123456789'
#    ciphertext = encryptor.encrypt(text)
#    print binascii.hexlify(ciphertext)
