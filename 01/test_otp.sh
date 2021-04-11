#!/bin/bash

echo "Test case 1:"
echo -n -e "\x85\xce\xa2\x25" > file.enc
echo -n -e "\xe4\xac\xe1\x2f" > file.key
./otp.py decrypt file.enc file.key file.plain
hexdump -C file.plain

echo "Test case 2:"
echo -n -e "\x00\x00\x61\x62\x43\x00" > file.plain
./otp.py encrypt file.plain file.key file.enc
./otp.py decrypt file.enc file.key fileorig.plain
hexdump -C fileorig.plain

