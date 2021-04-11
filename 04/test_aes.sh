#!/bin/bash

echo '$ echo -n "hello world" > plain'
echo -n "hello world" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

echo '$ echo -e -n "hello world \x01\x01\x02\x02" > plain'
echo -e -n "hello world \x01\x01\x02\x02" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

echo '$ echo -e -n "0123456789123456hello world \x01\x01\x02\x02" > plain'
echo -e -n "0123456789123456hello world \x01\x01\x02\x02" > plain
echo '$ ./aes.py -encrypt plain plain.enc'
./aes.py -encrypt plain plain.enc
rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new'
./aes.py -decrypt plain.enc plain.new
echo '$ hexdump -C plain.new'
hexdump -C plain.new
echo

rm -f plain.new
echo '$ ./aes.py -decrypt plain.enc plain.new [enter wrong pass]'
./aes.py -decrypt plain.enc plain.new
[ -e plain.new ] && echo "MAC failed but decryption performed?"

echo
rm -f big
echo '$ ./aes.py -decrypt big.enc big [password: bigfilepassword]'
./aes.py -decrypt big.enc big
echo '$ openssl dgst -sha256 big [066090dceeece702a28c9ab08677bd91f7e53fa6b5a69d1d4c3e9a2d556e4cee]'
openssl dgst -sha256 big
