#!/usr/bin/env python3

import sys
import os
import urllib.parse
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
    IV_attack = bytes()
    for i in range(0, len(text), C_SIZE):
        e_chunk = aes_encrypt(key, text[i:i+C_SIZE], XOR=e_chunk)
        encrypted += e_chunk
        if not IV_attack:
            # got C1
            IV_attack = e_chunk

    return encrypted,IV_attack


def CBC_decrypt(key, cipher, IV_Prime):
    decrypted = bytes()
    for i in range(C_SIZE, len(cipher), C_SIZE):
        prev_c_chunk = cipher[i-C_SIZE:i]
        if(i == C_SIZE * 2 and IV_Prime):
            prev_c_chunk = IV_Prime
        d_chunk = aes_decrypt(key, cipher[i:i+C_SIZE], XOR=prev_c_chunk)
        if(i != 0):
            decrypted += d_chunk
    return decrypted


def submit(key, str):
    url_encoded_key = urllib.parse.quoxte(str)
    input = "userid=456;userdata=" + url_encoded_key + ";session-id=31337"
    padded_input = add_padding(bytes(input, 'utf-8'))
    return CBC_encrypt(key, padded_input)


def verify(key, cipher, IV_Prime):
    decrypted_text = CBC_decrypt(key, cipher, IV_Prime)
    if bytes(";admin=true;", 'utf-8') in decrypted_text:
        return True
    return False


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
    cipher = CBC_encrypt(key, text)[0]
    open(outfile + "CBC_enc.bmp", "wb").write(header +
                                              cipher[:len(text)])
    msg = CBC_decrypt(key, cipher)
    open(outfile + "CBC_dec.bmp", "wb").write(header +
                                              msg[:len(text)])


def task2():
    # get input string from user
    input_str = sys.argv[2]
    attack = False
    IV_Prime = None
    if len(sys.argv) > 3  and sys.argv[3] == "attack":
        attack = True

    # generate a random key
    key = os.urandom(C_SIZE)

    # get encrypted cipher text and IV
    cipher_str, IV = submit(key, input_str)

    # calculate desired delta
    delta = xor(bytes("ata=zadminztruez".encode('utf-8')), bytes("ata=;admin=true;".encode('utf-8')))

    # inject delta to IV for the attack
    if attack == True:
        IV_Prime = xor(delta, IV)

    # verify the decrypted result
    print(verify(key, cipher_str, IV_Prime))

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
