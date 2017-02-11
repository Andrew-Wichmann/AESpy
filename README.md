# AESpy
I built this encryption script as an exercising in my computer security class. It was developed for educational purposes and not to actually be used in production. The Advanced Encryption Standard is a popular block cipher that encodes 128 bit blocks. It utilizes four functions:
+ SubByte
+ ShiftRows
+ MixCollumns
+ AddRoundKey

Each of these functions is implemented and works.
This repoistory also comes with a shell script to test the advantages of using OpenSSL instead of manual implementation and to ensure accurate encryption by the Python script.

## Example Usage
### Setup
+ First, install [Purdue's BitVector library] (https://engineering.purdue.edu/kak/dist/BitVector-3.4.5.html "Purdue's BitVector library")
+ Next, create your message
```bash
gedit message.txt
```
### Encryption
+ Try the encyption
```bash
python client.py message.txt enc
```
+ To write into a file
```bash
python client.py message.txt enc > cypher.txt
```
### Decryption
+ Try the decryption
```bash
python client.py cypher.txt dec
```

### Comparing to OpenSSL
+ Create you message
```bash
gedit message.txt
```
+ Run the shell script to compare performance between OpenSSL and my implementation
```bash
./checkEnc.sh
```

## Built with
+ Python
+ [Purdue's BitVector library] (https://engineering.purdue.edu/kak/dist/BitVector-3.4.5.html "Purdue's BitVector library")

## Authors
+ Andrew Wichmann AndrewWichmann@siu.edu

## License
This application is licensed under the MIT license.
