#!/usr/bin/env python3
import os, sys       # do not use any other imports/libraries
# took 4 hours (please specify here how much time your solution required)

def bn(b):
    n=0
    for byte in b:
        n = n << 8
        n = n | byte
    return n

def nb(n, length):
    bytes_array=[]
    for byte_index in range(0,length):
        current_byte = n & 0b11111111
        bytes_array.insert(0, current_byte)
        n = n >> 8
    return bytes(bytes_array)

def encrypt(pfile, kfile, cfile):
    b = open(pfile, 'rb').read()
    file_integer = bn(b)
    key_bytes = os.urandom(len(b))
    key_integer = bn(key_bytes)
    ciphertext_integer = file_integer ^ key_integer
    ciphertext_byte_string = nb(ciphertext_integer,len(b))
    open(kfile, 'wb').write(key_bytes)
    open(cfile, 'wb').write(ciphertext_byte_string)

def _xor_bytes(byte_object1, byte_object2):
    if not len(byte_object1) == len(byte_object2):
        raise Exception('xor for 2 byte objects of different lengths is not implemented')
    result = []
    for i in range(0, len(byte_object1)):
        byte1 = byte_object1[i]
        byte2 = byte_object2[i]
        xor_result = byte1 ^ byte2 
        result.append(xor_result)
    return bytes(result)

def decrypt(cfile, kfile, pfile):
    ciphertext_bytes = open(cfile, 'rb').read()
    key_bytes = open(kfile, 'rb').read()
    xor_result = _xor_bytes(ciphertext_bytes, key_bytes)
    open(pfile, 'wb').write(xor_result)

def usage():
    print("Usage:")
    print("encrypt <plaintext file> <output key file> <ciphertext output file>")
    print("decrypt <ciphertext file> <key file> <plaintext output file>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()

