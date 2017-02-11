#!/bin/bash

if [ ! -r message.txt ]; then
  printf '%s\n' 'No message to encrypt. Create a file named message.txt to start.'
  exit 1
fi

echo "ENCRYPTION"
echo "----------"
sslstart=$(date +%s%N)
openssl aes-128-ecb -e -nosalt -K "54686973206973206d79206b65792121" -in message.txt -out OpenSSLcypher.txt
sslfinish=$(date +%s%N)

mystart=$(date +%s%N)
python client.py message.txt enc > Mycypher.txt
myfinish=$(date +%s%N)

echo openssl timing $[$[$sslfinish/1000000]-$[$sslstart/1000000]]ms
echo my implementation timing $[$[$myfinish/1000000]-$[$mystart/1000000]]ms


sleep 2
if ! diff OpenSSLcypher.txt Mycypher.txt; then
  printf '%s\n' 'Ciphers differ!'
  else
  printf '%s\n' 'Cyphers identical!'
fi


sleep 2
echo
echo "DECRYPTION"
echo "----------"

sslstart=$(date +%s%N)
openssl aes-128-ecb -d -nosalt -K "54686973206973206d79206b65792121" -in OpenSSLcypher.txt -out SSLplain.txt
sslfinish=$(date +%s%N)

mystart=$(date +%s%N)
python client.py Mycypher.txt dec> Myplain.txt
myfinish=$(date +%s%N)

echo openssl timing $[$[$sslfinish/1000000]-$[$sslstart/1000000]]ms
echo my implementation timing $[$[$myfinish/1000000]-$[$mystart/1000000]]ms


sleep 2
if ! diff SSLplain.txt Myplain.txt; then
  printf '%s\n' 'Plaintexts differ!'
  else
  printf '%s\n' 'Plaintexts identical!'
fi
