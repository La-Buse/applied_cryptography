#!/usr/bin/env python3
import sys   # do not use any other imports/libraries

# took 10 hours (please specify here how much time your solution required)

def get_7bit_integers_from_int(int_value):
    int_array = []
    while int_value > 0:
        int_array.insert(0,int_value & 0b1111111)
        int_value = int_value >> 7
    return int_array

def bn(b):
    n=0
    for byte in b:
        n = n << 8
        n = n | byte
    return n

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
    # BOOLEAN encoder has been implemented for you
    if bool:
        bool = b'\xff'
    else:
        bool = b'\x00'
    return bytes([0x01]) + asn1_len(bool) + bool

def asn1_null():
    return bytes([5,0]) 

def asn1_integer(i):
    result = bytes([2]) #universal, primitive, tag 2 is 0b00000010 which is 2 in base 10
    value_bytes = bytes([0]) if i == 0 else nb(i)
    if (value_bytes[0] >> 7) == 1: #add padding if most significant bit is 1
        value_bytes = bytes([0]) + value_bytes
    result += asn1_len(value_bytes)
    result += value_bytes
    return result

def asn1_bitstring(bitstr):
    result = bytes([3]) #universal, primitive, tag 3 is 0b00000011 which is 3 in base 10
    if bitstr == "":
        return result + bytes([1,0]) #1: length 1 is 0b00000001 which is 1 in base 10, 0: representation of empty string
    remainder = len(bitstr) % 8
    padding_length = 8 - remainder if remainder != 0 else 0
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
    return bytes([0b00010011]) + asn1_len(string) + string

def asn1_utctime(time):
    return bytes([23]) + asn1_len(time) + time

def asn1_tag_explicit(der, tag):
    first_byte = bytes([0b10100000 | tag])
    length_bytes = asn1_len(der)
    return first_byte + length_bytes + der

asn1 = asn1_tag_explicit(asn1_sequence(asn1_set(asn1_integer(5) + asn1_tag_explicit(asn1_integer(200),2)
         + asn1_tag_explicit(asn1_integer(65407),11)) + asn1_boolean(True) 
         + asn1_bitstring("011") 
         + asn1_octetstring(b'\x00\x01\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02\x02')
         + asn1_null() + asn1_objectidentifier([1,2,840, 113549,1]) + asn1_printablestring(b'hello.')
         + asn1_utctime(b'250223010900Z')) # YYMMDDhhmmssZ
        ,0)
open(sys.argv[1], 'wb').write(asn1)
