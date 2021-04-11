#!/usr/bin/env python3

import codecs, datetime, hashlib, re, sys, socket # do not use any other imports/libraries
from urllib.parse import urlparse
from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ

# sudo apt install python3-pyasn1-modules
from pyasn1_modules import rfc2560, rfc5280

# took 6 hours (please specify here how much time your solution required)

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
def decode_asn1_len(bs):
    if bs[0] & 0b10000000 == 0b00000000:
        return 1, bs[0]
    nb_of_len_bytes = bs[0] & 0b01111111
    len_bytes = bs[1:nb_of_len_bytes+1]
    return 1+nb_of_len_bytes, bn(len_bytes)

def extract_bit_string(bitstring_octets):
    bitstring_octets=encoder.encode(bitstring_octets)
    bitstring_octets=bitstring_octets[1:]
    nb_of_len_bytes, _ = decode_asn1_len(bitstring_octets)
    bitstring = bitstring_octets[nb_of_len_bytes:]
    padding_length=bitstring[0]
    bitstring=bitstring[1:-1] + bytes([bitstring[-1] >> padding_length])
    return bitstring

def bytes_to_string(bs):
    str = ""
    for byte in bs:
        str += chr(byte)
    return str

def extract_content_length(response_string):
    if response_string=='':
        return -1
    content_length = re.search('content-length:\s*(\d+)\s', response_string, re.S+re.I).group(1)
    content_length = int(content_length)
    return content_length

def pem_to_der(content):
    # converts PEM-encoded X.509 certificate (if it is in PEM) to DER
    if content[:2] == b'--':
        content = content.replace(b"-----BEGIN CERTIFICATE-----", b"")
        content = content.replace(b"-----END CERTIFICATE-----", b"")
        content = codecs.decode(content, 'base64')
    return content

def get_name(cert):
    # gets subject DN from certificate
    name=decoder.decode(cert)[0][0][5]
    return name

def get_key(cert):
     # gets subjectPublicKey from certificate
    pk=decoder.decode(cert)[0][0][6]
    key=extract_bit_string(pk[1])
    return key

def get_serial(cert):
    # gets serial from certificate
    serial = decoder.decode(cert)[0][0][1]
    return int(serial)

def compute_hash(bytes):
    sha1 = hashlib.sha1()
    total_len=len(bytes)
    index=0
    while index < total_len:
        current = bytes[index:index+512]
        sha1.update(current)
        index+= 512
    digest = sha1.digest()
    return digest

def algorithm_identifier(obj_id):
    return asn1_sequence(asn1_objectidentifier(obj_id) + asn1_null())

def der_tbs_request(name, key, serial):
    STRING_OBJ_ID_SHA1 = [1,3,14,3,2,26]
    version=asn1_tag_explicit(asn1_integer(0),0)
    hash_key=compute_hash(key)
    hash_name=compute_hash(name)
    octet_string_key = asn1_octetstring(hash_key)
    octet_string_name = asn1_octetstring(hash_name)
    certificate_serial = asn1_integer(serial)
    request_list=asn1_sequence(
        asn1_sequence(
            asn1_sequence(
                algorithm_identifier(STRING_OBJ_ID_SHA1)
                + octet_string_name 
                + octet_string_key 
                + certificate_serial)
            )
        )
    return asn1_sequence(request_list)

def produce_request(cert, issuer_cert):
    # makes OCSP request in ASN.1 DER form

    # construct CertID (use SHA1)
    issuer_name = get_name(issuer_cert)
    issuer_key = get_key(issuer_cert)
    serial = get_serial(cert)

    print("[+] OCSP request for serial:", serial)

    # construct entire OCSP request
    issuer_name_encoded = encoder.encode(issuer_name)
    issuer_key_encoded = issuer_key
    tbs_request=der_tbs_request(issuer_name_encoded, issuer_key_encoded, serial)
    request = asn1_sequence(tbs_request)
    return request

def read_http_response_header(s):
    buffer_read = b''
    current_byte = s.recv(1)
    string_read=''
    if current_byte != b'':
        buffer_read = buffer_read + current_byte
        while buffer_read[-4:] != b'\r\n\r\n':
            current_byte = s.recv(1)
            buffer_read = buffer_read + current_byte
        string_read = bytes_to_string(buffer_read)
    return string_read

def get_http_response_length(response):
    content_length = extract_content_length(response)
    if content_length == -1:
        print('Failed to read response length')
        sys.exit(1)
    return content_length

def get_http_response_body(s, content_length):
    body_bytes = b''
    if content_length > 0:
        body_bytes = b''
        current_byte =0
        while current_byte != b'' and len(body_bytes) < content_length:
            current_byte=s.recv(1)
            body_bytes = body_bytes + current_byte
    if len(body_bytes) != content_length:
        print('Error: could not read the expected response length')
        sys.exit(1)
    return body_bytes

def send_req(ocsp_req, ocsp_url):
    url = urlparse(ocsp_url)
    host = url.netloc
    host_bytes = string_to_bytes(host)
    print("[+] Connecting to %s..." % (host))
    # connect to host
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))
    req_len = len(ocsp_req)
    content_length_str = 'Content-Length: ' + str(req_len)
    content_length_bytes = string_to_bytes(content_length_str) 
    # send HTTP POST request
    request_bytes = b'POST /' + b' HTTP/1.1\r\nHost: ' + host_bytes + b'\r\n' + content_length_bytes + b'\r\nContent-Type: application/ocsp-request\r\nConnection: close' + b'\r\n\r\n' + ocsp_req
    s.send(request_bytes)
    # read HTTP response header
    header=read_http_response_header(s)
    # get HTTP response length
    content_length = get_http_response_length(header)
    # read HTTP response body
    body_bytes = get_http_response_body(s, content_length)
    return body_bytes

def get_ocsp_url(cert):
    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    # looping over certificate extensions
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])=='1.3.6.1.5.5.7.1.1': # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])=='1.3.6.1.5.5.7.48.1': # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

    print("[-] OCSP url not found in the certificate!")
    exit(1)

def get_issuer_cert_url(cert):
    # gets the CA's certificate URL from the certificate's AIA extension (hint: see get_ocsp_url())
    # pyasn1 syntax description to decode AIA extension
    class AccessDescription(univ.Sequence):
      componentType = namedtype.NamedTypes(
        namedtype.NamedType('accessMethod', univ.ObjectIdentifier()),
        namedtype.NamedType('accessLocation', rfc5280.GeneralName()))

    class AuthorityInfoAccessSyntax(univ.SequenceOf):
      componentType = AccessDescription()

    authority_info_access_obj_id="1.3.6.1.5.5.7.1.1"
    ca_issuers_obj_id = "1.3.6.1.5.5.7.48.2"
    for seq in decoder.decode(cert)[0][0][7]:
        if str(seq[0])==authority_info_access_obj_id: # look for AIA extension
            ext_value = bytes(seq[1])
            for aia in decoder.decode(ext_value, asn1Spec=AuthorityInfoAccessSyntax())[0]:
                if str(aia[0])==ca_issuers_obj_id: # ocsp url
                    return str(aia[1].getComponentByName('uniformResourceIdentifier'))

def download_issuer_cert(issuer_cert_url):
    # downloads issuer certificate
    print("[+] Downloading issuer certificate from:", issuer_cert_url)

    # parse issuer certificate url
    url = urlparse(issuer_cert_url)

    # connect to host
    host=url.netloc
    netloc_bytes = string_to_bytes(host)
    path_bytes = string_to_bytes(url.path)

    # send HTTP GET request
    request_bytes = b'GET ' + path_bytes + b' HTTP/1.1\r\nHost: ' + netloc_bytes + b'\r\n\r\n'
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, 80))
    s.send(request_bytes)

    # read HTTP response header
    header=read_http_response_header(s)
    # get HTTP response length
    content_length = get_http_response_length(header)
    # read HTTP response body
    body_bytes = get_http_response_body(s, content_length)
    return body_bytes

def parse_ocsp_resp(ocsp_resp):
    # parses OCSP response
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()

    response = responseBytes.getComponentByName('response')

    basicOCSPResponse, _ = decoder.decode(
        response, asn1Spec=rfc2560.BasicOCSPResponse()
    )

    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')

    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)

    producedAt = datetime.datetime.strptime(str(tbsResponseData.getComponentByName('producedAt')), '%Y%m%d%H%M%SZ')
    certID = response0.getComponentByName('certID')
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')
    nextUpdate = datetime.datetime.strptime(str(response0.getComponentByName('nextUpdate')), '%Y%m%d%H%M%SZ')

    # let's assume that the certID in the response matches the certID sent in the request

    # let's assume that the response is signed by a trusted responder

    print("[+] OCSP producedAt:", producedAt)
    print("[+] OCSP thisUpdate:", thisUpdate)
    print("[+] OCSP nextUpdate:", nextUpdate)
    print("[+] OCSP status:", certStatus)

cert = pem_to_der(open(sys.argv[1], 'rb').read())
ocsp_url = get_ocsp_url(cert)
print("[+] URL of OCSP responder:", ocsp_url)

issuer_cert_url = get_issuer_cert_url(cert)
issuer_cert = download_issuer_cert(issuer_cert_url)

ocsp_req = produce_request(cert, issuer_cert)
ocsp_resp = send_req(ocsp_req, ocsp_url)


parse_ocsp_resp(ocsp_resp)
