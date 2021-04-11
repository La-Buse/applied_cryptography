#!/usr/bin/env python3

# do not use any other imports/libraries
import codecs
import datetime
import hashlib
import io
import sys
import zipfile

# apt-get install python3-bs4 python3-pyasn1-modules python3-m2crypto python3-lxml
import M2Crypto
import lxml.etree
from bs4 import BeautifulSoup
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560

# took 9 hours (please specify here how much time your solution required)

def bytes_to_string(bs):
    str = ""
    for byte in bs:
        str += chr(byte)
    return str

def verify_ecdsa(cert, signature_value, signed_hash):
    # verifies ECDSA signature given the hash value
    X509 = M2Crypto.X509.load_cert_der_string(cert)
    EC_pubkey = M2Crypto.EC.pub_key_from_der(X509.get_pubkey().as_der())

    # constructing r and s to satisfy M2Crypto
    l = len(signature_value)//2
    r = signature_value[:l]
    s = signature_value[l:]
    if r[0]>>7:
        r = b'\x00' + r
    if s[0]>>7:
        s = b'\x00' + s
    r = b'\x00\x00\x00' + bytes([len(r)]) + r
    s = b'\x00\x00\x00' + bytes([len(s)]) + s
    return EC_pubkey.verify_dsa(signed_hash, r, s)

def parse_tsa_response(timestamp_resp):
    # extracts from a TSA response the timestamp and timestamped DigestInfo
    timestamp = decoder.decode(timestamp_resp)
    tsinfo = decoder.decode(timestamp[0][1][2][1])[0]
    ts_digestinfo = encoder.encode(tsinfo[2])
    ts = datetime.datetime.strptime(str(tsinfo[4]), '%Y%m%d%H%M%SZ')
    # let's assume that the timestamp has been issued by a trusted TSA
    return ts, ts_digestinfo, None

def parse_ocsp_response(ocsp_resp):
    # extracts from an OCSP response certID_serial, certStatus and thisUpdate
    ocspResponse, _ = decoder.decode(ocsp_resp, asn1Spec=rfc2560.OCSPResponse())
    responseStatus = ocspResponse.getComponentByName('responseStatus')
    assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
    responseBytes = ocspResponse.getComponentByName('responseBytes')
    responseType = responseBytes.getComponentByName('responseType')
    assert responseType == rfc2560.id_pkix_ocsp_basic, responseType.prettyPrint()
    response = responseBytes.getComponentByName('response')
    basicOCSPResponse, _ = decoder.decode(response, asn1Spec=rfc2560.BasicOCSPResponse())
    tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
    response0 = tbsResponseData.getComponentByName('responses').getComponentByPosition(0)
    # let's assume that the OCSP response has been signed by a trusted OCSP responder
    certID = response0.getComponentByName('certID')
    # let's assume that the issuer name and key hashes in certID are correct
    certID_serial = certID[3]
    certStatus = response0.getComponentByName('certStatus').getName()
    thisUpdate = datetime.datetime.strptime(str(response0.getComponentByName('thisUpdate')), '%Y%m%d%H%M%SZ')

    return certID_serial, certStatus, thisUpdate

def canonicalize(full_xml, tagname):
    # returns XML canonicalization of an element with the specified tagname
    if type(full_xml)!=bytes:
        print("[-] canonicalize(): input is not a bytes object containing XML:", type(full_xml))
        exit(1)
    input = io.BytesIO(full_xml)
    et = lxml.etree.parse(input)
    output = io.BytesIO()
    lxml.etree.ElementTree(et.find('.//{*}'+tagname)).write_c14n(output)
    return output.getvalue()

def get_subject_cn(cert_der):
    # returns CommonName value from the certificate's Subject Distinguished Name field
    # looping over Distinguished Name entries until CN found
    for rdn in decoder.decode(cert_der)[0][0][5]:
        if str(rdn[0][0]) == '2.5.4.3': # CommonName
            return str(rdn[0][1])
    return ''

def sha_256(bytes_to_hash):
    sha256 = hashlib.sha256()
    index = 0
    current_bytes = bytes_to_hash[index:index+512]
    while current_bytes:
        sha256.update(current_bytes)
        index+=512
        current_bytes = bytes_to_hash[index:index+512]
    digest = sha256.digest()
    return digest

filename = sys.argv[1]

# get and decode XML
archive=zipfile.ZipFile(filename, 'r')
xml=archive.read('META-INF/signatures0.xml')
xmldoc = BeautifulSoup(xml, features='xml')

# let's trust this certificate
signers_cert_der = codecs.decode(xmldoc.XAdESSignatures.KeyInfo.X509Data.X509Certificate.encode_contents(), 'base64')
print("[+] Signatory:", get_subject_cn(signers_cert_der))

# perform all kinds of checks

#check timestamp
ts_der=codecs.decode(xmldoc.XAdESSignatures.SignatureTimeStamp.EncapsulatedTimeStamp.encode_contents(), 'base64')
ts, ts_digestinfo, attempt = parse_tsa_response(ts_der)
print("[+] Timestamped: %s +00:00" % (ts))
signature_value_canonicalized=canonicalize(xml,'SignatureValue')
hash_signature=sha_256(signature_value_canonicalized)
if hash_signature != decoder.decode(ts_digestinfo)[0][1].asOctets():
    print('[-] Error: computed hash of timestamped data does not match the one found in signature')
    sys.exit(1)

#check signed file hash
uri=xmldoc.XAdESSignatures.Signature.SignedInfo.Reference['URI']
ref_file_content=archive.read(uri)
hash_ref_file=sha_256(ref_file_content)
base_64_hash_ref_file=codecs.encode(hash_ref_file, 'base64')[:-1]
expected_hash=ref=xmldoc.XAdESSignatures.Signature.SignedInfo.Reference.DigestValue
expected_hash_content=expected_hash.encode_contents()
if base_64_hash_ref_file != expected_hash_content:
    print('[-] Error: computed hash of the file {0} does not match the digest value found in the signature'.format(uri))
    sys.exit(1)

#check certificate hash
cert_base_64=xmldoc.XAdESSignatures.Signature.KeyInfo.X509Data.X509Certificate.encode_contents()
cert_der=codecs.decode(cert_base_64, 'base64')
hash_cert=hashlib.sha256(cert_der).digest()
base64_cert=codecs.encode(hash_cert,'base64')[:-1]
base64_cert_expected=xmldoc.XAdESSignatures.Signature.Object.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.Cert.CertDigest.DigestValue.encode_contents()
if not base64_cert == base64_cert_expected:
    print('[-] Error: computed hash of the certificate does not match the hash found in signature')
    sys.exit(1)

#check signed properties
canonicalized_signed_properties=canonicalize(xml,'SignedProperties')
hash_canonicalized_signed_properties=sha_256(canonicalized_signed_properties)
computed_base64_signed_properties=codecs.encode(hash_canonicalized_signed_properties,'base64')[:-1]

expected_base64_digest=xmldoc.XAdESSignatures.Signature.SignedInfo.find('Reference',attrs={'Id':"S0-RefId0"}).DigestValue.encode_contents()
if computed_base64_signed_properties != expected_base64_digest:
    print('[-] Error: computed hash of SignedProperties does not match the one found in the signature')
    sys.exit(1)

#check ocsp response
signers_cert_der=codecs.decode(xmldoc.XAdESSignatures.Signature.KeyInfo.X509Data.X509Certificate.encode_contents(),'base64')
cert_serial=int(decoder.decode(signers_cert_der)[0][0][1])
ocsp_der=codecs.decode(xmldoc.XAdESSignatures.Signature.Object.QualifyingProperties.EncapsulatedOCSPValue.encode_contents(), 'base64')
certID_serial, certStatus, thisUpdate = parse_ocsp_response(ocsp_der)
if ts > thisUpdate:
    print('[-] Error: OCSP thisUpdate date is older than timestamp date')
    sys.exit(1)
if certStatus != 'good':
    print('[-] Error: OCSP status is not good')
    sys.exit(1)
if cert_serial != certID_serial:
    print('[-] Error: certificate serial in OCSP response does not match the one found in the signature')
    sys.exit(1)

# finally verify signatory's signature
signature_value=codecs.decode(xmldoc.XAdESSignatures.Signature.SignatureValue.encode_contents(),'base64')
signed_info_str=canonicalize(xml, 'SignedInfo')
signers_cert_der=codecs.decode(xmldoc.XAdESSignatures.Signature.KeyInfo.X509Data.X509Certificate.encode_contents(),'base64')
if verify_ecdsa(signers_cert_der, signature_value, hashlib.sha384(signed_info_str).digest()):
    print("[+] Signature verification successful!")
else:
    print("[-] Error: Signature verification failure!")
