from Crypto.Util import number
from math import gcd as bltin_gcd
import time

def generateRSAPrivateKey(e, Tn):
    d = 0
    x1 = 0
    x2 = 1
    y1 = 1
    temp = Tn

    while e > 0:
        temp1 = temp//e
        temp2 = temp - temp1 * e
        temp = e
        e = temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2 = x1
        x1 = x
        d = y1
        y1 = y

    if temp == 1:
        return d + Tn

def isCoprime(a, b):
    return bltin_gcd(a, b) == 1

def generateLargePrime(n):
    return number.getPrime(n)


def isPrime(a):
    if a > 1: 
        for i in range(2, a):
            if (a % i) == 0: 
                return False
        return True
    else:
        return False

def toitentEuler(p,q):
    return (p-1)*(q-1)

def RSAEncrypt(text,e,n):
    res = []
    for char in text:
        res.append(pow(ord(char),e,n))
    return res

def RSADecrypt(text,d,n):
    res = []
    for char in text:
        res.append(chr(pow(char,d,n)))
    return "".join(res)

# Elgamal ========================================

def convert_string_to_binary(input_string):
	binary = ''
	while len(input_string) > 0:
		if (input_string[0] == '\\') and (input_string[1] == 'x'):
			o = int(input_string[2:4], 16)
			input_string = input_string[4:]
		else :
			o = ord(input_string[0])
			input_string = input_string[1:]
		b = '{0:08b}'.format(o, 'b')
		binary += b
	
	return binary

def convert_binary_to_string(binary_string):
	# Defining splitting point 
	n = 8 
	binary_values = [(binary_string[i:i+n]) for i in range(0, len(binary_string), n)] 
	ascii_string = ""
	for binary_value in binary_values:
		an_integer = int(binary_value, 2) 
		if not chr(an_integer).isprintable():
			h = hex(an_integer)[2:]
			if (len(h) == 1):
				h = '0'+h

			character = '\\x' + h
		else :
			character = chr(an_integer)
		
		ascii_string += character


	return ascii_string

def add_filler(target, max_size):    
    fill = '1' if(target[-1] == '0') else '0'

    while(len(target) < max_size):
        target += fill

    return target

def remove_filler(slice_target):
	reverse = slice_target[::-1]
	sentinel = reverse[0]

	idx = 0
	while(reverse[idx] == sentinel):
		idx += 1
	reverse = reverse[idx:]

	return reverse[::-1]

def convert_int_to_binary(n, length):
    binary = '{0:b}'.format(n)
    binary = binary.zfill(length)
    return binary

def int_length(n):
	binary = '{0:b}'.format(n)

	return len(binary) - 1

def generateKeyElgamal(p) :
    g = random.randrange(1, p-1)
    x = random.randrange(1, p-2)
    y = (g**x) % p
    public = {
        "y" : y,
        "g" : g,
        "p" : p
    }

    private = {
        "x" : x,
        "p" : p
    }

    return public, private

def encryptElgamal(message, public):
    binary_length = int_length(public["p"])
    binary_message = convert_string_to_binary(message)

    plaintext_blocks = []

    message_length = len(binary_message) + binary_length - (len(binary_message) % binary_length)
    binary_message = add_filler(binary_message, message_length)
    # if (len(binary_message) % binary_length) != 0:
    #     message_length = len(binary_message) + binary_length - (len(binary_message) % binary_length)
    #     binary_message = binary_message.zfill(message_length)

    while len(binary_message) > 0 :
        plaintext_blocks.append(binary_message[:binary_length])
        binary_message = binary_message[binary_length:]
    
    k = random.randrange(1, public["p"] - 2)
    binary_ciphertext = ''
    for plaintext_block in plaintext_blocks :
        m = int(plaintext_block, 2)
        a = (public["g"] ** k) % public["p"]
        b = ((public["y"] ** k) * m) % public["p"]
        
        a = convert_int_to_binary(a, binary_length+1)
        b = convert_int_to_binary(b, binary_length+1)
        binary_ciphertext += a
        binary_ciphertext += b
    
    ciphertext_length = len(binary_ciphertext) + 8 - (len(binary_ciphertext) % 8)
    binary_ciphertext = add_filler(binary_ciphertext, ciphertext_length)
    ciphertext = convert_binary_to_string(binary_ciphertext)

    return ciphertext

def decryptElgamal(ciphertext, private):
    binary_ciphertext = convert_string_to_binary(ciphertext)
    binary_ciphertext = remove_filler(binary_ciphertext)
    binary_length = int_length(private["p"])
    block_length = (binary_length + 1) * 2
    
    ciphertext_blocks = []
    while len(binary_ciphertext) > 0 :
        ciphertext_blocks.append(binary_ciphertext[:block_length])
        binary_ciphertext = binary_ciphertext[block_length:]
    
    binary_plaintext = ''
    for ciphertext_block in ciphertext_blocks :
        a = ciphertext_block[:binary_length+1]
        b = ciphertext_block[binary_length+1:]

        a = int(a, 2)
        b = int(b, 2)

        inverse_ax = (a ** (private["p"] - 1 - private["x"])) % private["p"]
        m = (b * inverse_ax) % private["p"]
        m = convert_int_to_binary(m, binary_length)

        binary_plaintext += m
    
    binary_plaintext = remove_filler(binary_plaintext)
    plaintext = convert_binary_to_string(binary_plaintext)

    return plaintext

# Diffie-Hellman =========================================
def generateKeyDH(n, g, x, y):
    public_x = (g**x) % n
    public_y = (g**y) % n

    key = (public_x**y) % n
    # key = (public_y**x) % n
    
    return public_x, public_y, key

# plaintext || ciphertext == file ==============================================
def convert_bytes_to_binary(byte):
    return bin(int.from_bytes(byte, byteorder='big'))[2:]

def convert_binary_to_bytes(binary):
    v = int(binary, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

def convert_file_to_string(filepath):
    file = open(filepath, "rb")
    message_byte = file.read()
    message_binary = convert_bytes_to_binary(message_byte)
    if (len(message_binary) % 8) != 0:
        message_len = len(message_binary) + 8 - (len(message_binary) % 8)
        message_binary = message_binary.zfill(message_len)
    message_string = convert_binary_to_string(message_binary)
    file.close()

    return message_string

def convert_string_to_file(text, filepath):
    message_binary = convert_string_to_binary(text)
    message_byte = convert_binary_to_bytes(message_binary)
    
    file = open(filepath, "wb")
    file.write(message_byte)
    file.close()


def main():
    time0 = time.time()
    print("############ THIS IS ALICE ############")
    # while True:
    print("Generating Number...")
    p = generateLargePrime(1024)
    q = generateLargePrime(1024)
    print("P = " + str(p))
    print("Q = " + str(q))
        # if (isPrime(p) and isPrime(q)):
        #     break
        # else:
        #     print("p dan q harus prima!")
    n = p * q
    Tn = toitentEuler(p,q)
    while True:
        Pkey = generateLargePrime(512)
        if isCoprime(Pkey,Tn):
            break
        # else:
        #     print("Harus koprima dengan " + str(Tn))
    print(Pkey)
    print("############ THIS IS BOB ############")
    time1 = time.time() - time0
    plaintext = input("Masukkan Plaintext: ")
    time2 = time.time()
    print("Encrypting, please wait...")
    enc = RSAEncrypt(plaintext,Pkey,n)
    print("Encrypted: " + "".join(str(enc)))
    # print("hasil: ")
    # print (enc)

    print("############ THIS IS ALICE ############")
    d = generateRSAPrivateKey(Pkey,Tn)
    print("Decrypting, please wait...")
    dec = RSADecrypt(enc,d,n)
    print("Decryption: "+ dec)
    print("Time Elapsed: " + str(time.time() - time2 + time1) + " Seconds")

    # print("############ THIS IS BOB ############")
    # plaintext = input("Masukkan Plaintext: ")
    # enc = RSAEncrypt(plaintext,Pkey,n)
    # print("hasil: ")
    # print (enc)

    # print("############ THIS IS ALICE ############")
    # d = RSAPrivateKey(Pkey,Tn)
    # dec = RSADecrypt(enc,d,n)
    # print(dec)

    # # contoh pemakaian elgamal ====================
    # p = 7
    # public, private = generateKeyElgamal(p)
    # print(public)
    # print(private)
    # message = 'kalau simbol pager # atau at @ bisa ga ya'
    # print(message)

    # ciphertext = encryptElgamal(message, public)
    # print(ciphertext)

    # plaintext = decryptElgamal(ciphertext, private)
    # print(plaintext)

    # # contoh pemakaian diffie-hellman ================
    # n = 103
    # g = 10
    # x = 36
    # y = 58

    # public_x, public_y, key = generateKeyDH(n, g, x, y)
    # print(public_x)
    # print(public_y)
    # print(key)

    # # contoh pemakaian elgamal dari file  ====================
    # p = 7
    # public, private = generateKeyElgamal(p)
    # print(public)
    # print(private)

    # original_filename = 'test.jpg'
    # cipher_filename = 'cipherfile.jpg'
    # plain_filename = 'plainfile.jpg'

    # original_file = convert_file_to_string(original_filename)
    # print("ORIGINAL FILE =======================================================")
    # print(original_file)
    
    # ciphertext = encryptElgamal(original_file, public)
    # print("CIPHER FILE ==========================================================")
    # print(ciphertext)
    # convert_string_to_file(ciphertext, cipher_filename)

    # cipher_file = convert_file_to_string(cipher_filename)
    # print(cipher_file)
    # plaintext = decryptElgamal(cipher_file, private)
    
    # print("PLAIN FILE ==========================================================")
    # print(plaintext)
    # convert_string_to_file(plaintext, plain_filename)

main()


