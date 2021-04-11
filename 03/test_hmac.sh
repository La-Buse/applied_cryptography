#!/bin/bash

echo "key:testkey [MAC:a8be648dd48738b964391a00d4522fe988d10e3d5b2dbf8629a3dcbc0ce93ffd]"
echo '$ echo -e -n "\x01" > file_sha256'
echo -e -n "\x01" > file_sha256
echo '$ ./hmac.py -mac file_sha256'
./hmac.py -mac file_sha256

echo ""
echo '$ ./hmac.py -verify file_sha256'
./hmac.py -verify file_sha256

echo ""
echo "MD5 secretkey:"
echo '$ ./hmac.py -verify file_md5'
./hmac.py -verify file_md5

echo ""
echo "SHA1 secretkey:"
echo '$ ./hmac.py -verify file_sha1'
./hmac.py -verify file_sha1

echo ""
echo "SHA1 asd:"
echo '$ ./hmac.py -verify file_sha1'
./hmac.py -verify file_sha1
