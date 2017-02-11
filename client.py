import sys
import io
from BitVector import *

num_of_rounds=11

#AES modulus
modulus = BitVector( bitstring='100011011' )

#key_bitvector=BitVector(hexstring = "00000000000000000000000000000000")
#key_bitvector=BitVector(hexstring = "0f1571c947d9e8590cb7add6af7f6798")
key_bitvector = BitVector(textstring = "This is my key!!")
rcon=[BitVector(intVal = 1, size = 8), BitVector(intVal = 2,size=8), BitVector(intVal = 4, size=8), BitVector(intVal = 8,size=8), BitVector(intVal=16,size=8), BitVector(intVal = 32,size=8), BitVector(intVal = 64,size=8), BitVector(intVal = 128,size=8), BitVector(intVal = 27,size=8), BitVector(intVal = 54,size=8)]


##Initialize roundkey matrix as empty bitvectors
roundkey = [BitVector(size=128) for _ in range(num_of_rounds)]

def word_substitution(key,roud):

	##Make new vector for the return
	return_key = BitVector(intVal = key.intValue(), size = 32)

	##Shift left one byte
	return_key=return_key<<8
	
	i=0
	while i<=3:
		j=i*8
		k=(i+1)*8
		
		##Get byte in integer for table lookup
		tempbyte = return_key[j:k]
		z = tempbyte.intValue()

		##Find substitution in rijndael sbox table
		subbyte = sbox[z]

		##Make a bitvector out of the sbox result
		temp2 = BitVector(intVal=subbyte, size=8)

		##Replace the byte
		return_key[j:k] = temp2
		i=i+1


	##Add round constant
	return_key[:8]=rcon[roud-1] ^ return_key[:8]

	return return_key

def key_expansion():
	i=0
	
	##First key is the original key
	roundkey[0]=key_bitvector

	roud=1
	while roud<=(num_of_rounds-1):
		##Substitute word
		temp = word_substitution(roundkey[roud-1][96:128],roud)

		##XOR temp with first word of previous key for word 0		
		roundkey[roud][:32]= temp ^ roundkey[roud-1][:32]

		##XOR the previous word with previous key for word 1-3
		roundkey[roud][32:64]=roundkey[roud][:32]^roundkey[roud-1][32:64]
		roundkey[roud][64:96]=roundkey[roud][32:64]^roundkey[roud-1][64:96]
		roundkey[roud][96:128]=roundkey[roud][64:96]^roundkey[roud-1][96:128]

		##Move to the next key
		roud=roud+1


def subBytes(state):
	if(len(state)!=128):
		print "CRITICAL ERROR: State subsitution error in subBytes: vector is incorrect length"
	for x in range(16):
		j=x*8
		k=(x+1)*8		
		tempbyte = state[j:k]
		z = tempbyte.intValue()

		##Find substitution in rijndael sbox table
		subbyte = sbox[z]

		##Make a bitvector out of the sbox result
		temp2 = BitVector(intVal=subbyte, size=8)

		##Replace the byte
		state[j:k] = temp2
	return state

def shiftRows(state):
	if(len(state)!=128):
		print "CRITICAL ERROR: State row shift error in shiftRows: vector is incorrect length"
	tempstate = state[:]
	state[8:16] = tempstate[40:48]
	state[16:24] = tempstate[80:88]
	state[24:32] = tempstate[120:128]
	state[40:48] = tempstate[72:80]
	state[48:56] = tempstate[112:120]
	state[56:64] = tempstate[24:32]
	state[72:80] = tempstate[104:112]
	state[80:88] = tempstate[16:24]
	state[88:96] = tempstate[56:64]
	state[104:112] = tempstate[8:16]
	state[112:120] = tempstate[48:56]
	state[120:128] = tempstate[88:96]
	return state

def invShiftRows(state):
	if(len(state)!=128):
		print "CRITICAL ERROR: State row shift error in shiftRows: vector is incorrect length"
	tempstate = state[:]
	state[8:16] = tempstate[104:112]
	state[16:24] = tempstate[80:88]
	state[24:32] = tempstate[56:64]
	state[40:48] = tempstate[8:16]
	state[48:56] = tempstate[112:120]
	state[56:64] = tempstate[88:96]
	state[72:80] = tempstate[40:48]
	state[80:88] = tempstate[16:24]
	state[88:96] = tempstate[120:128]
	state[104:112] = tempstate[72:80]
	state[112:120] = tempstate[48:56]
	state[120:128] = tempstate[24:32]
	return state

def invMixCollumns(state):
	if(len(state)!=128):
		print "CRITICAL ERROR: State mix collumns error in mixCollumns: vector is incorrect length"
	
	state[:32] = invatrixMultiplication(state[:32])
	state[32:64] = invMatrixMultiplication(state[32:64])
	state[64:96] = invMatrixMultiplication(state[64:96])
	state[96:128] = invMatrixMultiplication(state[96:128])

	return state

def invMatrixMultiplication(vector):
	stateMatrix=vector[:]	
	stateMatrix[0:8] = modularMul(vector[0:8],"0E") ^ modularMul(vector[8:16], "0B") ^ modularMul(vector[16:24], "0D") ^ modularMul(vector[24:32], "09")
	stateMatrix[8:16] = modularMul(vector[0:8],"09") ^ modularMul(vector[8:16],"0E") ^ modularMul(vector[16:24],"0B") ^ modularMul(vector[24:32],"0D")
	stateMatrix[16:24] = modularMul(vector[0:8],"0D") ^ modularMul(vector[8:16],"09") ^ modularMul(vector[16:24],"0E") ^ modularMul(vector[24:32],"0B")
	stateMatrix[24:32] = modularMul(vector[0:8],"0B") ^ modularMul(vector[8:16],"0D") ^ modularMul(vector[16:24],"09") ^ modularMul(vector[24:32],"0E")
	return stateMatrix

def invSubBytes(state):
	if(len(state)!=128):
		print "CRITICAL ERROR: State subsitution error in subBytes: vector is incorrect length"
	for x in range(16):
		j=x*8
		k=(x+1)*8		
		tempbyte = state[j:k]
		#print "before",state[j:k].get_bitvector_in_hex()
		z = tempbyte.intValue()

		##Find substitution in rijndael rsbox table
		subbyte = rsbox[z]

		##Make a bitvector out of the sbox result
		temp2 = BitVector(intVal=subbyte, size=8)

		##Replace the byte
		state[j:k] = temp2
		#print "after:",state[j:k].get_bitvector_in_hex()
		#print
	return state


def modularMul(byte, hexNum):
	if(type(hexNum)!=str):
		print "CRITICAL ERROR: hexnum is not a string"
	a = BitVector( hexstring=hexNum)
	return a.gf_multiply_modular(byte, modulus, 8)

def matrixMultiplication(vector):
	stateMatrix=vector[:]	
	stateMatrix[0:8] = modularMul(vector[0:8],"02") ^ modularMul(vector[8:16],"03") ^ vector[16:24] ^ vector[24:32]
	stateMatrix[8:16] = vector[0:8] ^ modularMul(vector[8:16],"02") ^ modularMul(vector[16:24],"03") ^ vector[24:32]
	stateMatrix[16:24] = vector[0:8] ^ vector[8:16] ^ modularMul(vector[16:24],"02") ^ modularMul(vector[24:32],"03")
	stateMatrix[24:32] = modularMul(vector[0:8],"03") ^ vector[8:16] ^ vector[16:24] ^ modularMul(vector[24:32],"02")
	return stateMatrix

def mixCollumns(state):
	if(len(state)!=128):
		print "State mix collumns error in mixCollumns: vector is incorrect length"
	
	state[:32] = matrixMultiplication(state[:32])
	state[32:64] = matrixMultiplication(state[32:64])
	state[64:96] = matrixMultiplication(state[64:96])
	state[96:128] = matrixMultiplication(state[96:128])

	return state

def invMixCollumns(state):
	if(len(state)!=128):
		print "State mix collumns error in mixCollumns: vector is incorrect length"
	
	state[:32] = invMatrixMultiplication(state[:32])
	state[32:64] = invMatrixMultiplication(state[32:64])
	state[64:96] = invMatrixMultiplication(state[64:96])
	state[96:128] = invMatrixMultiplication(state[96:128])

	return state

def addRoundKey(roud, state):
	return state ^ roundkey[roud]

def encryption(message):
		
	plaintext = BitVector(textstring = message)
	if((len(plaintext)%128)!=0):
		padlen = 128 - (len(plaintext)%128)
		for _ in range(padlen/8):
			padding = BitVector(intVal=(padlen/8), size=8)
			plaintext = plaintext + padding
		#print "Padding",plaintext.get_bitvector_in_hex()
	stateMatrix = plaintext[:128]
	cypher = BitVector(size=0)
	block_count = 0
	num_of_blocks =len(plaintext)/128
	##loop until the message is all 0s 
	for blockNum in range(num_of_blocks):
		block_count = block_count+1
		stateMatrix = addRoundKey(0,stateMatrix)
		i=1

		while(i<num_of_rounds):
			stateMatrix = subBytes(stateMatrix)
			
			stateMatrix = shiftRows(stateMatrix)

			if(i!=num_of_rounds-1):
				stateMatrix = mixCollumns(stateMatrix)
			stateMatrix = addRoundKey(i, stateMatrix)

			i=i+1

		cypher = cypher+stateMatrix

		if(blockNum != (num_of_blocks-1)):
			plaintext = plaintext[128:]
			stateMatrix = plaintext[:128]
	if(len(sys.argv)==4):
		print "Block count",block_count
		print cypher.get_bitvector_in_hex()
	return cypher.get_bitvector_in_ascii()

def decryption(message):
	cypher = BitVector(textstring = message)
	stateMatrix = cypher[:128]
	plaintext = BitVector(size=0)

	block_count = 0	
	num_of_blocks =len(cypher)/128
	##loop until the message is all 0s
	for blockNum in range(num_of_blocks):
		block_count = block_count+1
		i=num_of_rounds-1

		stateMatrix = addRoundKey(i,stateMatrix)

		i=i-1
		while(i>=0):
			stateMatrix = invShiftRows(stateMatrix)
			
			stateMatrix = invSubBytes(stateMatrix)

			stateMatrix = addRoundKey(i, stateMatrix)

			if(i!=0):
				stateMatrix = invMixCollumns(stateMatrix)
			i=i-1

		plaintext = plaintext+stateMatrix
		if(blockNum != (num_of_blocks-1)):
			cypher = cypher[128:]
			stateMatrix = cypher[:128]
	if(len(sys.argv)==4):
		print "Block count",block_count
		print plaintext.get_bitvector_in_hex()
	ascii = plaintext.get_bitvector_in_ascii()
	return ascii[:len(ascii)-1]

    # Rijndael S-box
sbox =  [	0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,
            0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,
            0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1,
            0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05,
            0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83,
            0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,
            0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
            0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa,
            0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0,
            0x54, 0xbb, 0x16]

    # Rijndael Inverted S-box
rsbox = [	0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3,
            0x9e, 0x81, 0xf3, 0xd7, 0xfb , 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f,
            0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb , 0x54,
            0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b,
            0x42, 0xfa, 0xc3, 0x4e , 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24,
            0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25 , 0x72, 0xf8,
            0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d,
            0x65, 0xb6, 0x92 , 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
            0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84 , 0x90, 0xd8, 0xab,
            0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3,
            0x45, 0x06 , 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1,
            0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b , 0x3a, 0x91, 0x11, 0x41,
            0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6,
            0x73 , 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9,
            0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e , 0x47, 0xf1, 0x1a, 0x71, 0x1d,
            0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b ,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0,
            0xfe, 0x78, 0xcd, 0x5a, 0xf4 , 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07,
            0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f , 0x60,
            0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f,
            0x93, 0xc9, 0x9c, 0xef , 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5,
            0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61 , 0x17, 0x2b,
            0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55,
            0x21, 0x0c, 0x7d]

#plaintext = raw_input("Enter your plaintext: ")
#plaintext=plaintext.upper()
#print "Enter your key of size ", len(plaintext), " or less: "
#key = raw_input()
#key = key.upper()
f = open(sys.argv[1])
message = f.read()

key_expansion()
if(sys.argv[2] == "enc"):
	message = encryption(message)
	sys.stdout.write(message)
elif(sys.argv[2] == "dec"):
	message = decryption(message)
	sys.stdout.write(message)
else: 
	print "Usage: python client.py message.txt dec/enc"	

