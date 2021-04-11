#!/usr/bin/env python3

import datetime, os, sys
from pyasn1.codec.der import decoder

# $ sudo apt-get install python3-crypto
sys.path = sys.path[1:] # removes current directory from aes.py search path
from Crypto.Cipher import AES          # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.AES-module.html
from Crypto.Util.strxor import strxor  # https://www.dlitz.net/software/pycrypto/api/current/Crypto.Util.strxor-module.html#strxor
from hashlib import pbkdf2_hmac
import hashlib, hmac # do not use any other imports/libraries

# took 8 hours (please specify here how much time your solution required)

#==== ASN1 encoder start ====
def bn(b):
    n=0
    for byte in b:
        n = n << 8
        n = n | byte
    return n

def string_to_bytes(string):
    corresponding_integers = map(lambda x: ord(x), string)
    return bytes(corresponding_integers)

def nb(n):
    if n ==0:
        return bytes([0])
    b=b''
    while n > 0:
        current_byte = n & 0b11111111
        b = bytes([current_byte]) + b
        n = n >> 8
    return b

def asn1_len(bs):
    number_of_bytes = len(bs)
    if number_of_bytes == 0:
        return bytes([0])
    length_bytes = nb(number_of_bytes) #bytes encoding the number of value bytes
    if number_of_bytes > 127:
        #we want 1 as the most significant bit, and the rest of the bits as is
        first_byte = len(length_bytes) | 0b10000000 
        result = [first_byte]
        for b in length_bytes:
            result.append(b)
        return bytes(result)
    else:
        return bytes(length_bytes)

def asn1_boolean(bool):
    if bool:
        bool = bytes([0xff])
    else:
        bool = bytes([0x00])
    return bytes([0x01]) + asn1_len(bool) + bool

def asn1_null():
    return bytes([5,0]) 

def asn1_integer(i):
    result = bytes([2]) #universal, primitive, tag 2 is 0b00000010 which is 2 in base 10
    value_bytes = bytes([0]) if i == 0 else nb(i)
    if (value_bytes[0] >> 7) == 1:
        value_bytes = bytes([0]) + value_bytes
    result += asn1_len(value_bytes)
    result += value_bytes
    return result
    

def asn1_bitstring(bitstr):
    result = bytes([3]) #universal, primitive, tag 3 is 0b00000011 which is 3 in base 10
    if bitstr == "":
        return result + bytes([1,0]) #1: length 1 is 0b00000001 which is 1 in base 10, 0: representation of empty string
    padding_length = (8 - len(bitstr)) % 8
    padding_length_byte = nb(padding_length)
    padded_bitstr = bitstr + padding_length * "0"
    i=0
    string_integers = []
    while i < len(padded_bitstr):
        substring = padded_bitstr[i:i+8]
        substring_int = 0
        for bit_index in range(0,8):
            bit_value = 1 if substring[bit_index] == "1" else 0
            substring_int += (bit_value << (7-bit_index))
        string_integers.append(substring_int)
        i += 8
    value_bytes = padding_length_byte + bytes(string_integers)
    result = result + asn1_len(value_bytes)
    return result + value_bytes
        
def asn1_octetstring(octets):
    return bytes([4]) + asn1_len(octets) + octets

def get_7bit_integers_from_int(int_value):
    int_array = []
    while int_value > 0:
        int_array.insert(0,int_value & 0b1111111)
        int_value = int_value >> 7
    return int_array

def asn1_objectidentifier(oid):
    if oid == []:
        return bytes([6, 0])
    id_byte = bytes([6]) #universal, primitive, tag 6 is 0b000000110 which is 6 base 10
    first_element = oid[0] if len(oid) > 0 else 0
    second_element = oid[1] if len(oid) > 1 else 0
    first_value_byte = bytes([40*first_element + second_element])
    other_bytes = b''

    if len(oid) > 2:
        for i in range(2, len(oid)):
            int_array = get_7bit_integers_from_int(oid[i])
            for i in range(0,len(int_array)-1):
                int_array[i] = int_array[i] | 0b10000000 #each element except the last should have leftmost bit at 1 
            other_bytes = other_bytes + bytes(int_array)
    length_byte = asn1_len(first_value_byte + other_bytes)
    return id_byte + length_byte + first_value_byte + other_bytes
    

def asn1_sequence(der):
    return bytes([0b00110000]) + asn1_len(der) + der

def asn1_set(der):
    return bytes([0b00110001]) + asn1_len(der) + der

def asn1_printablestring(string):
    value_bytes = string_to_bytes(string)
    return bytes([0b00010011]) + asn1_len(value_bytes) + value_bytes

def asn1_utctime(time):
    value_bytes = string_to_bytes(time)
    return bytes([23]) + asn1_len(value_bytes) + value_bytes

def asn1_tag_explicit(der, tag):
    first_byte = bytes([0b10100000 | tag])
    length_bytes = asn1_len(der)
    return first_byte + length_bytes + der

#==== ASN1 encoder end ====

def _add_padding(bs, block_size):
    padding = b''
    unused_bytes = block_size - (len(bs) % block_size)
    padding = unused_bytes * bytes([unused_bytes])
    return bs + padding

def _asn1_pbkdf2params(salt, iter, key_length):
    return asn1_sequence(asn1_octetstring(salt) + asn1_integer(iter) + asn1_integer(key_length))
    
def _asn1_aes_info(algo_obj_id, iv):
    return asn1_sequence(asn1_objectidentifier(algo_obj_id) + asn1_octetstring(iv))

def _encode_digest_info(obj_id, digest):
    return asn1_sequence(asn1_sequence(asn1_objectidentifier(obj_id) + asn1_null()) + asn1_octetstring(digest))

def _append_to_binary_file(appended, appendee):
    with open(appendee, 'rb') as file:
        bytes = file.read(512)
        while bytes:
            open(appended, 'ab').write(bytes)
            bytes = file.read(512)

def _decode_asn1_len(bs):
    if bs[0] & 0b10000000 == 0b00000000:
        return 1, bs[0]
    nb_of_len_bytes = bs[0] & 0b01111111
    len_bytes = bs[1:nb_of_len_bytes+1]
    return 1+nb_of_len_bytes, bn(len_bytes)

def _remove_padding(plaintext):
    return plaintext[:-plaintext[-1]]

def _calculate_digest(filename, iv, h, offset=0):
    with open(filename, 'rb') as file:
        file.seek(offset)
        bytes = iv + file.read(512-len(iv))
        while bytes:
            h.update(bytes)
            bytes = file.read(512)
    return h.digest()

def _aes_encrypt(pfile, cipher, iv, block_size):
    current_iv = iv
    ciphertext = b''
    padding_added=False
    with open(pfile, 'rb') as file:
        current_block = file.read(block_size)
        while current_block:
            if len(current_block) < block_size:
                current_block = _add_padding(current_block, block_size)
                padding_added=True
            current_iv = cipher.encrypt(strxor(current_block, current_iv))
            ciphertext += current_iv    
            current_block = file.read(block_size)
        if not padding_added:
            padding = bytes([block_size]) * block_size
            ciphertext += cipher.encrypt(strxor(padding, current_iv))
    return ciphertext

def _aes_decrypt(cfile, cipher, iv, block_size, offset):
    current_iv = iv
    plaintext= b''
    with open(cfile, 'rb') as file:
        file.seek(offset)
        bytes = file.read(block_size)
        while bytes:
            decrypted = strxor(cipher.decrypt(bytes), current_iv)
            current_iv = bytes
            bytes = file.read(block_size)
            plaintext += decrypted
    return plaintext

def get_hash_name_and_function(object_identifier):
    STRING_OBJ_ID_MD5 = "1.2.840.113549.2.5"
    STRING_OBJ_ID_SHA1 = "1.3.14.3.2.26"
    STRING_OBJ_ID_SHA256 = "2.16.840.1.101.3.4.2.1"
    if object_identifier == STRING_OBJ_ID_MD5:
        hash_algo = hashlib.md5
    elif object_identifier == STRING_OBJ_ID_SHA1:
        hash_algo = hashlib.sha1
    else:
        hash_algo = hashlib.sha256
    return hash_algo


def benchmark():
    NB_ITERATIONS = 10000
    start = datetime.datetime.now()
    pbkdf2_hmac('sha1', b'asd', os.urandom(16), NB_ITERATIONS, 48)
    end = datetime.datetime.now()
    time = (end-start).total_seconds()
    iter = int(NB_ITERATIONS/time)
    print ("[+] Benchmark: %s PBKDF2 iterations in 1 second" % (iter))
    return iter

def encrypt(pfile, cfile):

    KEY_LENGTH = 48
    TMP_FILENAME = pfile+'.tmp'

    iter = benchmark()
    pwd = input('[?] Enter password: ')
    salt = os.urandom(8)
    key = hashlib.pbkdf2_hmac('sha1', string_to_bytes(pwd), salt, iter, KEY_LENGTH)
    aes_key = key[0:16]
    hmac_key = key[16:]

    iv_current = os.urandom(AES.block_size)
    cipher = AES.new(aes_key)
    ciphertext = _aes_encrypt(pfile, cipher, iv_current, 16)
    open(TMP_FILENAME, 'wb').write(ciphertext)
    h = hmac.new(hmac_key, None, hashlib.sha256)
    digest = _calculate_digest(TMP_FILENAME, iv_current, h)

    enc_info = asn1_sequence(
        _asn1_pbkdf2params(salt, iter, KEY_LENGTH) +
        _asn1_aes_info([2,16,840,1,101,3,4,1,2], iv_current) + 
        _encode_digest_info([2,16,840,1,101,3,4,2,1], digest)
    )
    open(cfile, 'wb').write(enc_info)

    _append_to_binary_file(cfile, TMP_FILENAME)

    os.remove(TMP_FILENAME)

def decrypt(cfile, pfile):
    # reading DER structure
    ten_first_bytes = open(cfile, 'rb').read(10)
    nb_of_len_bytes, nb_of_remaining_bytes = _decode_asn1_len(ten_first_bytes[1:]) #remove first byte since it is the id of the sequence
    nb_of_der_bytes = 1+nb_of_len_bytes+nb_of_remaining_bytes #1+ is the sequence code
    der = open(cfile, 'rb').read(nb_of_der_bytes)
    decoded = decoder.decode(der)
    salt = decoded[0][0][0].asOctets()
    iter = int(decoded[0][0][1])
    key_length = int(decoded[0][0][2])
    iv = decoded[0][1][1].asOctets()
    digest = decoded[0][2][1].asOctets()
    hash_function_obj_id = str(decoded[0][2][0][0])

    # asking for password
    pwd = input('[?] Enter password: ')

    # derieving key
    key = hashlib.pbkdf2_hmac('sha1', string_to_bytes(pwd), salt, iter, key_length)
    aes_key = key[0:16]
    hmac_key = key[16:]
    # first pass over ciphertext to calculate and verify HMAC
    hash_function = get_hash_name_and_function(hash_function_obj_id)
    h = hmac.new(hmac_key, None, hash_function)
    calculated_digest = _calculate_digest(cfile, iv, h, nb_of_der_bytes)
    if not hmac.compare_digest(digest,calculated_digest):
        print('[-] HMAC verification failure: wrong password or modified ciphertext!')

    # second pass over ciphertext to decrypt
    else:
        cipher = AES.new(aes_key)
        plaintext = _aes_decrypt(cfile, cipher, iv, 16, nb_of_der_bytes)
        plaintext = _remove_padding(plaintext)
        open(pfile, 'wb').write(plaintext)

def usage():
    print("Usage:")
    print("-encrypt <plaintextfile> <ciphertextfile>")
    print("-decrypt <ciphertextfile> <plaintextfile>")
    sys.exit(1)

if len(sys.argv) != 4:
    usage()
elif sys.argv[1] == '-encrypt':
    encrypt(sys.argv[2], sys.argv[3])
elif sys.argv[1] == '-decrypt':
    decrypt(sys.argv[2], sys.argv[3])
else:
    usage()
