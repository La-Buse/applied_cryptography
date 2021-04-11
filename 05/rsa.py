#!/usr/bin/env python3

import codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder

# took 4 hours (please specify here how much time your solution required)


def nb(i, length=False):
    # converts integer to bytes
    b = b''
    if length==False:
        length = (i.bit_length()+7)//8
    for _ in range(length):
        b = bytes([i & 0xff]) + b
        i >>= 8
    return b

def bn(b):
    # converts bytes to integer
    i = 0
    for char in b:
        i <<= 8
        i |= char
    return i

#==== ASN1 encoder start ====
def string_to_bytes(string):
    corresponding_integers = map(lambda x: ord(x), string)
    return bytes(corresponding_integers)

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

def encode_digest_info(obj_id, digest):
    return asn1_sequence(asn1_sequence(asn1_objectidentifier(obj_id) + asn1_null()) + asn1_octetstring(digest))
#==== ASN1 encoder end ====
def _find_first_null_byte_index(bs):
    index = 0
    for byte in bs:
        if byte == 0:
            return index
        index+=1
    return -1

def _random_bytes(length):
    result = b''
    i=0
    while i < length:
        current_byte = os.urandom(1)
        while current_byte == b'\x00':
            current_byte = os.urandom(1)
        result = result + current_byte
        i+=1
    return result

def pem_to_der(content):
    PUBLIC_KEY_HEADER='-----BEGIN PUBLIC KEY-----'
    PRIVATE_KEY_HEADER='-----BEGIN RSA PRIVATE KEY-----'
    PUBLIC_KEY_FOOTER='-----END PUBLIC KEY-----'
    PRIVATE_KEY_FOOTER='-----END RSA PRIVATE KEY-----'

    if type(content) == str and PUBLIC_KEY_HEADER in content:
        content = content.replace(PUBLIC_KEY_HEADER, '')
        content = content.replace(PUBLIC_KEY_FOOTER, '')
        content = content.replace('\r','').replace('\n', '')
        content_bytes = string_to_bytes(content)
        der = codecs.decode(content_bytes, 'base64')
        decoded = decoder.decode(der) 
        return decoded
    elif type(content) == str and PRIVATE_KEY_HEADER in content:
        content = content.replace(PRIVATE_KEY_HEADER, '')
        content = content.replace(PRIVATE_KEY_FOOTER, '')
        content = content.replace('\r','').replace('\n', '')
        content_bytes = string_to_bytes(content)
        der = codecs.decode(content_bytes, 'base64')
        decoded = decoder.decode(der) 
        return decoded
    else:
        return decoder.decode(content)

def get_pubkey(filename):
    try:
        file_content = open(filename, 'r').read()
    except Exception as e:
        file_content = open(filename, 'rb').read()
    decoded_der = pem_to_der(file_content)
    bitstring = decoded_der[0][1]
    decoded_bitstring = decoder.decode(bitstring.asOctets())
    modulus = int(decoded_bitstring[0][0])
    public_exponent = int(decoded_bitstring[0][1])
    return modulus, public_exponent

def get_privkey(filename):
    try:
        file_content = open(filename, 'r').read()
    except Exception as e:
        file_content = open(filename, 'rb').read()
    decoded_der = pem_to_der(file_content)
    n = int(decoded_der[0][1])
    d = int(decoded_der[0][3])
    return n,d

def pkcsv15pad_encrypt(plaintext, n):
    n_bytes = nb(n)
    padding_length = len(n_bytes) - len(plaintext) - 3 #3 is for the default padding bytes 0x0002 and 0x00
    # plaintext must be at least 11 bytes smaller than modulus
    if len(n_bytes) - len(plaintext) < 11:
        print('[+] Halt: plaintext must be at least 11 bytes smaller than modulus') 
        sys.exit(1)
    padding = _random_bytes(padding_length)
    result =  b'\x00\x02' + padding + b'\x00' + plaintext
    return result

def pkcsv15pad_sign(plaintext, n):
    padded_plaintext = b'\x00\x01'
    n_bytes = nb(n)
    padding_length = len(n_bytes) - len(plaintext) - 3 #3 is for the default padding bytes 0x0001 and 0x00
    if len(n_bytes) - len(plaintext) < 3:
        print('[+] Halt: plaintext must be at least 3 bytes smaller than modulus')
        sys.exit(1)
    padding = b'\xff' * padding_length
    return padded_plaintext + padding + b'\x00' + plaintext

def pkcsv15pad_remove(plaintext):
    plaintext = plaintext[2:]
    plaintext = plaintext[_find_first_null_byte_index(plaintext)+1:]
    return plaintext

def encrypt(keyfile, plaintextfile, ciphertextfile):
    n, e = get_pubkey(keyfile)
    plaintext = open(plaintextfile, 'rb').read()
    padded = pkcsv15pad_encrypt(plaintext, n)
    padded_int = bn(padded)
    encrypted_int = pow(padded_int, e, n)
    encrypted_bytes = nb(encrypted_int)
    open(ciphertextfile, 'wb').write(encrypted_bytes)

def decrypt(keyfile, ciphertextfile, plaintextfile):
    ciphertext = open(ciphertextfile, 'rb').read()
    ciphertext_int = bn(ciphertext)
    n,d=get_privkey(keyfile)
    decrypted_int = pow(ciphertext_int, d, n)
    decrypted = nb(decrypted_int)
    decrypted = pkcsv15pad_remove(decrypted)
    open(plaintextfile, 'wb').write(decrypted)

def digestinfo_der(filename):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as file:
        bytes = file.read(512)
        while bytes:
            sha256.update(bytes)
            bytes = file.read(512)
        digest = sha256.digest()
        der = encode_digest_info([2,16,840,1,101,3,4,2,1], digest)
        return der

def sign(keyfile, filetosign, signaturefile):
    der = digestinfo_der(filetosign)
    n,d = get_privkey(keyfile)
    modulus_byte_size = len(nb(n))
    padded_der = pkcsv15pad_sign(der, n)
    padded_der_int = bn(padded_der)
    signature_int = pow(padded_der_int, d, n)    
    signature_bytes = nb(signature_int, modulus_byte_size)
    open(signaturefile, 'wb').write(signature_bytes)

def verify(keyfile, signaturefile, filetoverify):
    n,e = get_pubkey(keyfile)
    signature_bytes = open(signaturefile, 'rb').read()
    signature_int = bn(signature_bytes)
    decrypted_int = pow(signature_int, e, n)
    decrypted_bytes = nb(decrypted_int)
    digest_info = pkcsv15pad_remove(decrypted_bytes)
    decoded_digest_info = decoder.decode(digest_info)
    
    digest = decoded_digest_info[0][1].asOctets()
    calculated_digest_info = digestinfo_der(filetoverify)
    if digest_info == calculated_digest_info:
        print('Verified OK')
    else:
        print('Verification Failure')

def usage():
    print("Usage:")
    print("encrypt <public key file> <plaintext file> <output ciphertext file>")
    print("decrypt <private key file> <ciphertext file> <output plaintext file>")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'encrypt':
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'decrypt':
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'sign':
    sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
