import random

def gcd(a, b): 
    if (a == 0 or b == 0):
        return 0
    if (a == b):
        return a  
    if (a > b):  
        return gcd(a - b, b) 
              
    return gcd(a, b - a) 
    
def isCoprime(a, b): 
    return gcd(a, b) == 1

def toitentEuler(p,q):
    return (p-1)*(q-1)

def RSAPrivateKey(e,Tn):
    k = 1
    while True:
        res = (1 + k*Tn) / e
        if res.is_integer():
            break
        k += 1
    return res

def processString(text):
    text = text.upper()
    text = text.replace(" ", "")
    res = ''
    for i in range(len(text)):
        temp = str(ord(text[i]) - 65)
        if (len(temp) == 1):
            temp = "0" + temp
        res = res + str(temp)
    return res

def returnProcessedString(text):
    res = ''
    for i in range(len(text) // 2):
        temp = int(text[i*2:(i*2)+2]) + 65
        res = res + chr(temp)
    return res

def splitBlock(text):
    while True:
        if (len(text) % 4 != 0):
            text = text + '0'
        else:
            break
    res = []
    for i in range(int(len(text)/4)):
        res.append(text[i*4:(i*4)+4])
    return res

def RSA(block,e,n):
    enc = []
    for i in range(len(block)):
        res = str(pow(int(block[i]),int(e),int(n)))
        while True:
            if (len(res) % 4 != 0):
                res = "0" + res
            else:
                break
        enc.append(res)
    return enc

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




def main():
    print("############ THIS IS ALICE ############")
    p = int(input("masukkan p: "))
    q = int(input("masukkan q: "))
    n = int(p) * int(q)
    Tn = toitentEuler(p,q)
    Pkey = int(input("input public key: "))

    print("############ THIS IS BOB ############")
    plaintext = input("Masukkan Plaintext: ")
    plaintext = plaintext.upper()
    processed = processString(plaintext)
    print(processed)
    block = splitBlock(processed)
    enc = RSA(block,Pkey,n)
    print ("".join(enc))

    print("############ THIS IS ALICE ############")
    d = RSAPrivateKey(Pkey,Tn)
    dec = RSA(enc,d,n)
    text = "".join(dec)
    print(text)
    text = returnProcessedString(text)
    print(text)

    # # contoh pemakaian elgamal
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


main()


