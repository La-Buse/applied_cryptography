#!/usr/bin/env python3

import argparse, codecs, hashlib, os, sys # do not use any other imports/libraries
from pyasn1.codec.der import decoder, encoder

# took 6 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='issue TLS server certificate based on CSR', add_help=False)
parser.add_argument("CA_cert_file", help="CA certificate (in PEM or DER form)")
parser.add_argument("CA_private_key_file", help="CA private key (in PEM or DER form)")
parser.add_argument("csr_file", help="CSR file (in PEM or DER form)")
parser.add_argument("output_cert_file", help="File to store certificate (in PEM form)")
args = parser.parse_args()

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
    for byte in b:
        i <<= 8
        i |= byte
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
    

def asn1_bitstring(octets):
    result = bytes([3]) + asn1_len(octets + b'\x00') + b'\x00' + octets
    return result
        
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

def _encode_subject_public_key_info(obj_id, n, e):
    return asn1_sequence(
        asn1_sequence(asn1_objectidentifier(obj_id) + asn1_null()) +
        asn1_bitstring(
                asn1_sequence(
                    asn1_integer(n) + asn1_integer(e)
                )
        )
    )

def _encode_algorithm_identifier():
    return asn1_sequence(
        asn1_objectidentifier([1,2,840,113549,1,1,11]) + asn1_null()
    )

def _encode_key_usage():
    return asn1_sequence(
        asn1_objectidentifier([2,5,29,15]) +
        asn1_boolean(True) +
        asn1_octetstring(
            asn1_bitstring(bytes([1 << 7]))
        )
    )

def _encode_extended_key_usage():
    return asn1_sequence(
        asn1_objectidentifier([2,5,29,37]) +
        asn1_boolean(True) +
        asn1_octetstring(
            asn1_sequence(
                asn1_objectidentifier([1,3,6,1,5,5,7,3,1])
            )
        )
    )

def _encode_basic_constraints():
    return asn1_sequence(
        asn1_objectidentifier([2,5,29,19]) +
        asn1_boolean(True) +
        asn1_octetstring(
            asn1_sequence(
                asn1_boolean(False)
            )
        )
    )

def _encode_validity():
    start = "210324000000Z"
    end = "220324000000Z"
    return asn1_sequence(
        asn1_utctime(start) + asn1_utctime(end)
    )

def _bitstring_to_int(bitstring):
    int_value = 0
    len_bitstring = len(bitstring)
    for bit_index in range(0,len(bitstring)):
        bit_value = 1 if bitstring[bit_index] == "1" else 0
        int_value += (bit_value << (len_bitstring-1-bit_index))
    return int_value

def _bitstring_to_bytes(bitstring):
    index = 0
    len_bitstring = len(bitstring)
    result = b''
    while index < len_bitstring:
        current_byte = bitstring[index:index+8]
        byte_int = _bitstring_to_int(current_byte)
        result = result + bytes([byte_int])
        index += 8
    return result

def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----END CERTIFICATE REQUEST-----", b"")
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN RSA PRIVATE KEY-----", b"")
        content = content.replace(b"-----END RSA PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    file_content = open(filename, 'rb').read()
    decoded_der = decoder.decode(pem_to_der(file_content))
    n = int(decoded_der[0][1])
    e = int(decoded_der[0][2])
    d = int(decoded_der[0][3])
    return n,e,d

def pkcsv15pad_sign(plaintext, n):
    padded_plaintext = b'\x00\x01'
    n_bytes = nb(n)
    padding_length = len(n_bytes) - len(plaintext) - 3 #3 is for the default padding bytes 0x0001 and 0x00
    if len(n_bytes) - len(plaintext) < 3:
        print('[+] Halt: plaintext must be at least 3 bytes smaller than modulus')
        exit(1)
    padding = b'\xff' * padding_length
    return padded_plaintext + padding + b'\x00' + plaintext

def digestinfo_der(m):
    sha256 = hashlib.sha256()
    index = 0
    bytes = m[index:index+512]
    while bytes:
        sha256.update(bytes)
        index+=512
        bytes = m[index:index+512]
    digest = sha256.digest()
    der = encode_digest_info([2,16,840,1,101,3,4,2,1], digest)
    return der


def sign(m, keyfile):
    digest_info = digestinfo_der(m)
    n, e, d = get_privkey(keyfile)
    padded = pkcsv15pad_sign(digest_info, n)
    padded_int = bn(padded)
    signature = pow(padded_int, d, n)
    modulus_byte_length = len(nb(n))
    signature_bytes = nb(signature, modulus_byte_length)
    return signature_bytes


def get_subject_cn(csr_der):
    entries = csr_der[0][0][1]
    for e in entries:
        if str(e[0][0]) == "2.5.4.3":
            return e[0][1] 

def get_subjectPublicKeyInfo(csr_der):
    bitstring = csr_der[0][0][2][1]
    bytes_representation = _bitstring_to_bytes(str(bitstring))
    decoded = decoder.decode(bytes_representation)
    return int(decoded[0][0]),int(decoded[0][1])

def get_subjectName(cert_der):
    return encoder.encode(decoder.decode(cert_der)[0][0][5])

def issue_certificate(private_key_file, issuer, subject, pubkey):
    CERTIFICATE_HEADER = "-----BEGIN CERTIFICATE-----\n"
    CERTIFICATE_FOOTER = "-----END CERTIFICATE-----\n"

    n, e, d = get_privkey(private_key_file)
    version = asn1_tag_explicit(asn1_integer(2), 0)
    serial_number = asn1_integer(666)
    signature = _encode_algorithm_identifier()
    subject_public_key_info_der = _encode_subject_public_key_info([1,2,840,113549,1,1,1],n,e)
    extensions = asn1_tag_explicit(asn1_sequence(
        _encode_key_usage() +
        _encode_extended_key_usage() +
        _encode_basic_constraints()    
    ), 3)
    tbs_certificate = asn1_sequence(
        version + 
        serial_number + 
        signature + 
        issuer + 
        _encode_validity() +
        subject +
        subject_public_key_info_der
         + extensions
    )
    tbs_certificate_signature = sign(tbs_certificate,private_key_file) 
    signature_der = asn1_bitstring(tbs_certificate_signature)
    der = asn1_sequence(tbs_certificate + _encode_algorithm_identifier() + signature_der)
    open('test.cert.der', 'wb').write(der)
    base64_bytes = codecs.encode(der, 'base64')
    base64_message = base64_bytes.decode('ascii')
    pem = CERTIFICATE_HEADER + base64_message + CERTIFICATE_FOOTER
    return pem

# obtain subject's CN from CSR
csr_der = decoder.decode(pem_to_der(open(args.csr_file, 'rb').read()))
subject_cn_text = get_subject_cn(csr_der)

print("[+] Issuing certificate for \"%s\"" % (subject_cn_text))

# obtain subjectPublicKeyInfo from CSR
pubkey = get_subjectPublicKeyInfo(csr_der)

# construct subject name DN for end-entity's certificate
subject = asn1_sequence(asn1_set(asn1_sequence(asn1_objectidentifier([2,5,4,3]) + asn1_printablestring(subject_cn_text))))

# get subject name DN from CA certificate
CAcert = pem_to_der(open(args.CA_cert_file, 'rb').read())
CAsubject = get_subjectName(CAcert)

# issue certificate
cert_pem = issue_certificate(args.CA_private_key_file, CAsubject, subject, pubkey)
open(args.output_cert_file, 'w').write(cert_pem)