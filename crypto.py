#!/usr/bin/env python3

import sys
import os
# from tools import *
from Crypto.Cipher import AES
import binascii
C_SIZE = 16


def xor(byte1, byte2):
    return bytes(a ^ b for a, b in zip(byte1, byte2))


def aes_encrypt(key, msg, XOR=None):
    if(XOR):
        msg = xor(msg, XOR)
    _AES = AES.new(key, AES.MODE_ECB)
    cipher = _AES.encrypt(msg)
    return cipher


def aes_decrypt(key, cipher, XOR=None):
    _AES = AES.new(key, AES.MODE_ECB)
    msg = _AES.decrypt(cipher)
    if(XOR):
        msg = xor(msg, XOR)
    return msg


def add_padding(text):
    pad_len = C_SIZE - (len(text) % C_SIZE)
    text += bytes([pad_len]) * pad_len
    return text


def ECB_encrypt(key, text):
    text = add_padding(text)
    print(len(text))
    encrypted = bytes()
    for i in range(0, len(text), C_SIZE):
        e_chunk = aes_encrypt(key, text[i:i+C_SIZE])
        encrypted += e_chunk
    return encrypted


def ECB_decrypt(key, cipher):
    decrypted = bytes()
    for i in range(0, len(cipher), C_SIZE):
        d_chunk = aes_decrypt(key, cipher[i:i+C_SIZE])
        decrypted += d_chunk
    return decrypted


def CBC_encrypt(key, text):
    IV = os.urandom(C_SIZE)
    text = add_padding(text)

    e_chunk = IV
    encrypted = bytes(IV)
    for i in range(0, len(text), C_SIZE):
        e_chunk = aes_encrypt(key, text[i:i+C_SIZE], XOR=e_chunk)
        encrypted += e_chunk
    return encrypted


def CBC_decrypt(key, cipher):
    decrypted = bytes()
    for i in range(C_SIZE, len(cipher), C_SIZE):
        prev_c_chunk = cipher[i-C_SIZE:i]
        d_chunk = aes_decrypt(key, cipher[i:i+C_SIZE], XOR=prev_c_chunk)
        if(i != 0):
            decrypted += d_chunk
    return decrypted


def task1():
    infile = sys.argv[2]
    outfile = sys.argv[3]

    file_bytes = open(infile, 'rb').read()

    # Separate header from text
    splitat = 54
    header, text = file_bytes[:splitat], file_bytes[splitat:]

    key = os.urandom(C_SIZE)
    cipher = ECB_encrypt(key, text)
    open(outfile + "ECB_enc.bmp", "wb").write(header + cipher[:len(text)])
    msg = ECB_decrypt(key, cipher)
    open(outfile + "ECB_dec.bmp", "wb").write(header + msg[:len(text)])

    key = os.urandom(C_SIZE)
    cipher = CBC_encrypt(key, text)
    open(outfile + "CBC_enc.bmp", "wb").write(header +
                                              cipher[:len(text)])
    msg = CBC_decrypt(key, cipher)
    open(outfile + "CBC_dec.bmp", "wb").write(header +
                                              msg[:len(text)])


'''



'''


def task2():
    # Modify image file with 54 byte header

    infile = sys.argv[2]
    outfile = sys.argv[3]


def task3():
    # Modify image file with 54 byte header

    infile = sys.argv[2]
    outfile = sys.argv[3]

    file_bytes = open(infile, 'rb').read()

    # Separate header from text
    splitat = 54
    header, text = file_bytes[:splitat], file_bytes[splitat:]

    # Encrypt text
    key = random_bytes(len(text))

    encrypted = xor_otp(text, key)

    # Write encryption to file
    open(outfile, "wb").write(header + encrypted)

    # See if decryption is correct
    decrypted = xor_otp(encrypted, key)
    checkDecryption(text, decrypted)


def task4():
    infile1 = sys.argv[2]
    infile2 = sys.argv[3]
    outfile = sys.argv[4]

    file_bytes1 = open(infile1, 'rb').read()
    file_bytes2 = open(infile2, 'rb').read()

    # Separate header from text
    splitat = 54
    header = file_bytes1[:splitat]
    text1 = file_bytes1[splitat:]
    text2 = file_bytes2[splitat:]

    # Encrypt text
    key = random_bytes(len(text1))

    encrypted1 = xor_otp(text1, key)
    encrypted2 = xor_otp(text2, key)

    # Try revert, by xor-ing encryptions
    try_decrypt = xor_bytes(encrypted1, encrypted2)

    # Write xor decryption to file
    open(outfile, "wb").write(header + try_decrypt)


def main():

    flag = sys.argv[1]

    if(flag[0] != '-'):
        raise Exception("Invalid Flag")

    if(flag == '-1'):
        task1()
    elif(flag == '-2'):
        task2()
    elif(flag == '-3'):
        task3()

if __name__ == "__main__":
    main()
