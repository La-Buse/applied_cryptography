#!/usr/bin/env python3

import argparse, codecs, sys     # do not use any other imports/libraries
from smartcard.CardType import AnyCardType
from smartcard.CardRequest import CardRequest
from smartcard.CardConnection import CardConnection
from smartcard.util import toHexString


# took 2 hours (please specify here how much time your solution required)

# parse arguments
parser = argparse.ArgumentParser(description='Fetch certificates from ID card', add_help=False)
parser.add_argument('--cert', type=str, default=None, choices=['auth','sign'], help='Which certificate to fetch')
parser.add_argument("--out", required=True, type=str, help="File to store certificate (PEM)")
args = parser.parse_args()


# this will wait until a card is inserted in any reader
channel = CardRequest(timeout=100, cardType=AnyCardType()).waitforcard().connection
print("[+] Selected reader:", channel.getReader())

# using T=0 for compatibility and simplicity
try:
    channel.connect(CardConnection.T0_protocol)
except:
    # fallback to T=1 if the reader does not support T=0
    channel.connect(CardConnection.T1_protocol)

# detect and print the EstEID card platform
atr = channel.getATR()
if atr == [0x3B,0xFE,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0x45,0x73,0x74,0x45,0x49,0x44,0x20,0x76,0x65,0x72,0x20,0x31,0x2E,0x30,0xA8]:
    print("[+] EstEID v3.x on JavaCard")
elif atr == [0x3B,0xFA,0x18,0x00,0x00,0x80,0x31,0xFE,0x45,0xFE,0x65,0x49,0x44,0x20,0x2F,0x20,0x50,0x4B,0x49,0x03]:
    print("[+] EstEID v3.5 (10.2014) cold (eID)")
elif atr == [0x3B,0xDB,0x96,0x00,0x80,0xB1,0xFE,0x45,0x1F,0x83,0x00,0x12,0x23,0x3F,0x53,0x65,0x49,0x44,0x0F,0x90,0x00,0xF1]:
    print("[+] Estonian ID card (2018)")
else:
    print("[-] Unknown card:", toHexString(atr))
    sys.exit(1)

def send(apdu):
    data, sw1, sw2 = channel.transmit(apdu)

    # success
    if [sw1,sw2] == [0x90,0x00]:
        return data
    # (T=0) card signals how many bytes to read
    elif sw1 == 0x61:
        #print("[=] More data to read:", sw2)
        return send([0x00, 0xC0, 0x00, 0x00, sw2]) # GET RESPONSE of sw2 bytes
    # (T=0) card signals incorrect Le
    elif sw1 == 0x6C:
        #print("[=] Resending with Le:", sw2)
        return send(apdu[0:4] + [sw2]) # resend APDU with Le = sw2
    # probably error condition
    else:
        print("Error: %02x %02x, sending APDU: %s" % (sw1, sw2, toHexString(apdu)))
        sys.exit(1)

def extract_length_from_asn_header(bytes):
    first = bytes[0]
    if first & 0b10000000 == 0b10000000:
        nb_of_length_bytes = first & 0b01111111
        interesting_bytes = bytes[1:nb_of_length_bytes+1]
        return 2+nb_of_length_bytes,bn(interesting_bytes)
    else:
        return 2, first 

def bn(b):
    # b - bytes to encode as integer
    n=0
    for byte in b:
        n = n << 8
        n = n | byte
    return n 

# reading from the card auth or sign certificate
print("[=] Retrieving %s certificate..." % (args.cert))
send([0x00,0xA4,0x04,0x00,0x10,0xA0,0x00,0x00,0x00,0x77,0x01,0x08,0x00,0x07,0x00,0x00,0xFE,0x00,0x00,0x01,0x00])
#select MF
send([0x00, 0xA4, 0x00, 0x0C])
if args.cert == 'auth':
    #select MF/ADF1
    send([0x00, 0xA4, 0x00, 0x0C]+[0x02, 0xad, 0xf1])
    #select MF/ADF1/3401
    send([0x00, 0xA4, 0x00, 0x0C]+[0x02, 0x34, 0x01])
else:
    #select MF/ADF2
    send([0x00, 0xA4, 0x00, 0x0C]+[0x02, 0xad, 0xf2])
    #select MF/ADF2/
    send([0x00, 0xA4, 0x00, 0x0C]+[0x02, 0x34, 0x1f])
# read binary
r = send([0x00, 0xB0, 0x00, 0x00, 0x00])

# read the first 10 bytes to parse ASN.1 length field and determine certificate length
#select AID

r_bytes = bytes(r)
index, certlen = extract_length_from_asn_header(r_bytes[1:11])
first_bytes = r_bytes[:index]
start = len(r_bytes)
r_bytes = r_bytes[index:]
print("[+] Certificate size: %d bytes" % (certlen))

# reading DER-encoded certificate from the smart card
remaining = certlen - len(r_bytes)
array = [r]
i=0
offset = start
p1p2 = [offset>>8, offset&0xff]

while remaining > 231: 
    current_bytes = send([0x00, 0xB0] + p1p2 + [0x00])
    array.append(current_bytes)
    r_bytes = r_bytes + bytes(current_bytes)
    remaining = certlen - len(r_bytes)
    i+=1
    offset = start + i * 231
    p1p2 = [offset>>8, offset&0xff]

r_bytes = r_bytes + bytes(send([0x00, 0xB0] + p1p2 + [remaining]))
r_bytes = first_bytes + r_bytes
base64_bytes = codecs.encode(r_bytes, 'base64')

# save certificate in PEM format
open(args.out,"wb").write(b"-----BEGIN CERTIFICATE-----\n"+base64_bytes+b"-----END CERTIFICATE-----\n")
print ("[+] Certificate stored in", args.out)