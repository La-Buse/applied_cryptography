#!/usr/bin/python3

# sudo apt install python3-gmpy2
import codecs, hashlib, os, sys # do not use any other imports/libraries
import gmpy2
from secp256r1 import curve
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

# --------------- asn1 DER encoder
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


# --------------- asn1 DER encoder end


def pem_to_der(content):
    # converts PEM content (if it is PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN PUBLIC KEY-----", b"")
        content = content.replace(b"-----END PUBLIC KEY-----", b"")
        content = content.replace(b"-----BEGIN EC PRIVATE KEY-----", b"")
        content = content.replace(b"-----END EC PRIVATE KEY-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_privkey(filename):
    file_content = open(filename, 'rb').read()
    decoded_der = decoder.decode(pem_to_der(file_content))
    octetstring = decoded_der[0][1]
    d = bn(octetstring.asOctets())
    return d

def get_pubkey(filename):
    file_content = open(filename, 'rb').read()
    decoded_der = decoder.decode(pem_to_der(file_content))
    ec_point = decoded_der[0][1].asOctets()
    ec_point = ec_point[1:]
    len_xy=int(len(ec_point)/2)
    x = ec_point[:len_xy]
    y = ec_point[len_xy:]
    return (bn(x),bn(y))

def calculate_sha384_hash(filename):
    h=hashlib.sha384()
    with open(filename, 'rb') as file:
        bytes = file.read(512)
        while bytes:
            h.update(bytes)
            bytes = file.read(512)
    return h.digest()

def get_k(length,n):
    done=False
    while not done:
        k=bn(os.urandom(length))
        if k > 0 and k < n:
            done = True
    return k
        

def ecdsa_sign(keyfile, filetosign, signaturefile):

    d = get_privkey(keyfile)
    hash = calculate_sha384_hash(filetosign)
    order_bytes = nb(curve.n)
    truncated_hash = hash[:len(order_bytes)]
    hash_integer = bn(truncated_hash)
    k = get_k(len(order_bytes), curve.n)
    R = curve.mul(curve.g, k)
    r = R[0]
    k_inverse = gmpy2.invert(k,curve.n)
    s=(k_inverse*(hash_integer+r*d))%(curve.n)
    signature = asn1_sequence(asn1_integer(r)+asn1_integer(s))
    open(signaturefile, 'wb').write(signature)

def ecdsa_verify(keyfile, signaturefile, filetoverify):
    Q=get_pubkey(keyfile)
    der_decoded = decoder.decode(open(signaturefile, 'rb').read())
    r,s=int(der_decoded[0][0]),int(der_decoded[0][1])
    s_inverse = gmpy2.invert(s,curve.n)
    h=calculate_sha384_hash(filetoverify)
    order_bytes = nb(curve.n)
    h=h[:len(order_bytes)]
    h_integer = bn(h)
    left_side = curve.mul(curve.g, h_integer*s_inverse)
    R=curve.add(left_side, curve.mul(Q,(r*s_inverse)))
    if R[0] == r:
        print("Verified OK")
    else:
        print("Verification failure")

def usage():
    print("Usage:")
    print("sign <private key file> <file to sign> <signature output file>")
    print("verify <public key file> <signature file> <file to verify>")
    sys.exit(1)

#ecdsa_sign('priv.pem', 'filetosign', 'signature')
#print('end of program')

if len(sys.argv) != 5:
    usage()
elif sys.argv[1] == 'sign':
    ecdsa_sign(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == 'verify':
    ecdsa_verify(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    usage()
