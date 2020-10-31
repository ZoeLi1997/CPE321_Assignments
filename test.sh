#!/bin/bash

./decrypt.py -c -1 ./encrypted\ 4/caesar_hard_encrypt.txt


./decrypt.py -c -1 ./encrypted\ 4/caesar_hard_2_encrypt.txt


./decrypt.py -c -1 ./encrypted\ 4/caesar_easy_encrypted.txt


./decrypt.py -c -1 ./encrypted\ 4/caesar_easy_2_encrypted.txt


./decrypt.py -m '{"S":"O", "L":"I", "N":"G", "F":"S", "W":"U", "R":"D", "D":"Y", "C":"V", "Z":"A", "A":"W", "U":"F", "T":"M", "P":"J", "E":"Z"}' ./encrypted\ 4/mono_easy_encrypt.txt


./decrypt.py -m '{"H":"H", "X":"E", "J":"N", "Y":"S", "O":"W", "W":"K", "R":"U", "P":"G", "I":"B", "I":"B", "U":"Y", "M":"C", "T":"J", "N":"V"}' ./encrypted\ 4/mono_medium_encrypt.txt


./decrypt.py -v "./encrypted 4/vigerene_easy_encrypted.txt"


./decrypt.py -v "./encrypted 4/vigerene_medium_encrypt.txt"


./decrypt.py -v "./encrypted 4/vigerene_hard_encrypt.txt"
