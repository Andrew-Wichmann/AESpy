#!/bin/bash
echo "ENCRYPTION!"
sslstart=$(date +%s%N)
openssl aes-128-ecb -e -nosalt -K "54686973206973206d79206b65792121" -in message.txt -out cypher.txt
sslfinish=$(date +%s%N)

mystart=$(date +%s%N)
python client.py message.txt enc > cypher2.txt
myfinish=$(date +%s%N)

echo openssl timing $[$[$sslfinish/1000000]-$[$sslstart/1000000]]ms
echo my implementation timing $[$[$myfinish/1000000]-$[$mystart/1000000]]ms

diff cypher.txt cypher2.txt
wc cypher.txt
wc cypher2.txt

echo
echo "DECRYPTION!"

sslstart=$(date +%s%N)
openssl aes-128-ecb -d -nosalt -K "54686973206973206d79206b65792121" -in cypher.txt -out sslplain.txt
sslfinish=$(date +%s%N)

mystart=$(date +%s%N)
python client.py cypher2.txt dec> myplain.txt
myfinish=$(date +%s%N)

echo openssl timing $[$[$sslfinish/1000000]-$[$sslstart/1000000]]ms
echo my implementation timing $[$[$myfinish/1000000]-$[$mystart/1000000]]ms

diff cypher.txt cypher2.txt
wc cypher.txt
wc cypher2.txt
