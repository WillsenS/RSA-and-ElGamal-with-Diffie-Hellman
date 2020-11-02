from Crypto.Util import number
from math import gcd as bltin_gcd
import time
import random

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
    print(g)
    print(x)
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

def convert_list_to_file(ls, filepath):
    f=open(filepath,'w')
    for i in ls:
        f.write(str(i)+'\n')
    f.close()

def convert_file_to_list(filepath):
    with open(filepath) as f:
        content = f.readlines()
    content = [x.strip() for x in content]
    return content 

def saveKey(key, filename):
    output = ''
    for i in key:
        output += str(key[i])
        output += '\n'
    
    output_file = open(filename, "w")
    output_file.writelines(output)
    output_file.close()

def loadElgamalPublicKey(filename):
    input_file = open(filename, "r")
    temp = input_file.readlines()
    input_file.close() 
    
    public_key = {
        'y' : int(temp[0].strip('\n')),
        'g' : int(temp[1].strip('\n')),
        'p' : int(temp[2].strip('\n'))
    }

    return public_key

def loadElgamalPrivateKey(filename):
    input_file = open(filename, "r")
    temp = input_file.readlines()
    input_file.close() 
    
    private_key = {
        'x' : int(temp[0].strip('\n')),
        'p' : int(temp[1].strip('\n'))
    }

    return private_key

def loadRSAPublicKey(filename):
    input_file = open(filename, "r")
    temp = input_file.readlines()
    input_file.close() 
    
    public_key = {
        'e' : int(temp[0].strip('\n')),
        'n' : int(temp[1].strip('\n'))
    }

    return public_key

def loadRSAPrivateKey(filename):
    input_file = open(filename, "r")
    temp = input_file.readlines()
    input_file.close() 
    
    private_key = {
        'p' : int(temp[0].strip('\n')),
        'q' : int(temp[1].strip('\n')),
        'd' : int(temp[2].strip('\n'))
    }

    return private_key
    
def main():
    # menu
    while True:
        print("================== Menu =======================")
        print("1. Pembangkitan kunci RSA")
        print("2. Encrypt RSA")
        print("3. Decrypt RSA")
        print("4. Pembangkitan kunci Elgamal")
        print("5. Encrypt Elgamal")
        print("6. Decrypt Elgamal")
        print("7. Pembangkitan kunci sesi Diffie-Hellman")
        print("8. Pembangkitan bilangan prima")
        print("9. Exit")
        chosen_menu = input("Pilih nomor menu yang diinginkan : ")

        if chosen_menu == '1' :
            print("Masukkan cara generate key: ")
            print("1. Auto generate")
            print("2. Input manual")
            choose = input("Pilihan: ")
            if choose == "1" :
                length = int(input("Masukkan panjang kunci: "))
                p = generateLargePrime(length)
                q = generateLargePrime(length)
                n = p * q
                Tn = toitentEuler(p,q)
                while True:
                    e = generateLargePrime(length // 2)
                    if isCoprime(e,Tn):
                        break
            if choose == "2" :
                p = int(input("Masukkan bilangan prima p: "))
                q = int(input("Masukkan bilangan prima q: "))

                n = p * q
                Tn = toitentEuler(p,q) 
                while True:
                    print("Masukkan bilangan prima e yang koprima dengan", Tn, ": ", end="")
                    e = int(input())
                    if isCoprime(e, Tn):
                        break
                    else :
                        print("e belum koprima dengam", Tn, ", silakan ulangi!")
            
            d = generateRSAPrivateKey(e, Tn)
            public = {
                "e" : e,
                "n" : n
            }

            private = {
                "p" : p,
                "q" : q,
                "d" : d
            }

            print("Kunci public rsa : ", public)
            print("Kunci privat rsa : ", private)
            is_saving = input("Apakah anda ingin menyimpan kunci (ya/tidak) : ")

            if is_saving == 'ya':
                public_key_filename = input("Nama file untuk kunci publik: ")
                private_key_filename = input("Nama file untuk kunci privat: ")
                
                saveKey(public, public_key_filename)
                saveKey(private, private_key_filename)
                print("Penyimpanan berhasil")
        elif chosen_menu == '2':
            print("========== Pilihan Sumber Plainteks ==============")
            print("1. File")
            print("2. Manual")
            chosen_input = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_input == '1':
                plaintext_filename = input("Nama file untuk plainteks: ")
                plaintext = convert_file_to_string(plaintext_filename)
                print(plaintext)
            elif chosen_input == '2':
                plaintext = input("Plainteks: ")
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            print("========== Pilihan Sumber Kunci Publik ==============")
            print("1. File")
            print("2. Manual")
            chosen_key = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_key == '1':
                public_key_filename = input("Nama file untuk kunci publik: ")
                public = loadRSAPublicKey(public_key_filename)
            elif chosen_key == '2':
                e = input("e : ")
                n = input("n : ")

                public = {
                    'e' : int(e),
                    'n' : int(n),
                }
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            time0 = time.time()
            ciphertext = RSAEncrypt(plaintext,public["e"],public["n"])
            time1 = time.time()
            
            print("Ciphertext : ", ciphertext)
            print("Waktu Pemrosesan Enkripsi : ", time1-time0, "seconds")

            is_saving = input("Apakah anda ingin menyimpan cipherteks (ya/tidak) : ")

            if is_saving == 'ya':
                cipherteks_filename = input("Nama file untuk cipherteks : ")
                convert_list_to_file(ciphertext, cipherteks_filename)
                print("Penyimpanan berhasil")

        elif chosen_menu == '3':
            print("========== Pilihan Sumber Cipherteks ==============")
            print("1. File")
            print("2. Manual")
            chosen_input = input("Pilih nomor pilihan yang diinginkan : ")
            if chosen_input == '1':
                ciphertext_filename = input("Nama file untuk plainteks: ")
                ciphertext = convert_file_to_list(ciphertext_filename)
                ciphertext = [int(i) for i in ciphertext]
                print(ciphertext)
            elif chosen_input == '2':
                ciphertext = input("Cipherteks (pisah dengan spasi): ")
                ciphertext = list(ciphertext.split(" "))
                ciphertext = [int(i) for i in ciphertext]
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            print("========== Pilihan Sumber Kunci Privat ==============")
            print("1. File")
            print("2. Manual")
            chosen_key = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_key == '1':
                private_key_filename = input("Nama file untuk kunci privat: ")
                private = loadRSAPrivateKey(private_key_filename)
            elif chosen_key == '2':
                p = input("p : ")
                q = input("q : ")
                d = input("d : ")

                private = {
                    'p' : int(p),
                    'q' : int(q),
                    'd' : int(d)
                }
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            time0 = time.time()
            plaintext = RSADecrypt(ciphertext, private["d"], private["p"] * private["q"])
            time1 = time.time()
            
            print("Plainteks : ", plaintext)
            print("Waktu Pemrosesan Dekripsi : ", time1-time0, "seconds")

            is_saving = input("Apakah anda ingin menyimpan plainteks (ya/tidak) : ")

            if is_saving == 'ya':
                plaintext_filename = input("Nama file untuk plainteks : ")
                convert_string_to_file(plaintext, plaintext_filename)
                print("Penyimpanan berhasil")
        elif chosen_menu == '4':
            while True:
                p = int(input("Masukkan bilangan prima p: "))
                if isPrime(p):
                    break
                else:
                    print("Bilangan p yang dimasukkan belum prima, silakan ulangi!")

            public, private = generateKeyElgamal(p)
            print("Kunci public elgamal : ", public)
            print("Kunci privat elgamal : ", private)
            is_saving = input("Apakah anda ingin menyimpan kunci (ya/tidak) : ")

            if is_saving == 'ya':
                public_key_filename = input("Nama file untuk kunci publik: ")
                private_key_filename = input("Nama file untuk kunci privat: ")
                
                saveKey(public, public_key_filename)
                saveKey(private, private_key_filename)
                print("Penyimpanan berhasil")
        elif chosen_menu == '5':
            print("========== Pilihan Sumber Plainteks ==============")
            print("1. File")
            print("2. Manual")
            chosen_input = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_input == '1':
                plaintext_filename = input("Nama file untuk plainteks: ")
                plaintext = convert_file_to_string(plaintext_filename)
                print(plaintext)
            elif chosen_input == '2':
                plaintext = input("Plainteks: ")
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            print("========== Pilihan Sumber Kunci Publik ==============")
            print("1. File")
            print("2. Manual")
            chosen_key = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_key == '1':
                public_key_filename = input("Nama file untuk kunci publik: ")
                public = loadElgamalPublicKey(public_key_filename)
            elif chosen_key == '2':
                y = input("y : ")
                g = input("g : ")
                p = input("p : ")

                public = {
                    'y' : int(y),
                    'g' : int(g),
                    'p' : int(p),
                }
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            time0 = time.time()
            ciphertext = encryptElgamal(plaintext, public)
            time1 = time.time()
            
            print("Ciphertext : ", ciphertext)
            print("Waktu Pemrosesan Enkripsi : ", time1-time0, "seconds")
            is_saving = input("Apakah anda ingin menyimpan cipherteks (ya/tidak) : ")

            if is_saving == 'ya':
                cipherteks_filename = input("Nama file untuk cipherteks : ")
                convert_string_to_file(ciphertext, cipherteks_filename)
                print("Penyimpanan berhasil")
        elif chosen_menu == '6':
            print("========== Pilihan Sumber Cipherteks ==============")
            print("1. File")
            print("2. Manual")
            chosen_input = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_input == '1':
                ciphertext_filename = input("Nama file untuk plainteks: ")
                ciphertext = convert_file_to_string(ciphertext_filename)
                print(ciphertext)
            elif chosen_input == '2':
                ciphertext = input("Cipherteks: ")
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            print("========== Pilihan Sumber Kunci Privat ==============")
            print("1. File")
            print("2. Manual")
            chosen_key = input("Pilih nomor pilihan yang diinginkan : ")
            
            if chosen_key == '1':
                private_key_filename = input("Nama file untuk kunci privat: ")
                private = loadElgamalPrivateKey(private_key_filename)
            elif chosen_key == '2':
                x = input("x : ")
                p = input("p : ")

                private = {
                    'x' : int(x),
                    'p' : int(p)
                }
            else :
                print("ERROR: pilihan tidak tersedia!")
                continue
            
            time0 = time.time()
            plaintext = decryptElgamal(ciphertext, private)
            time1 = time.time()

            print("Plainteks : ", plaintext)
            print("Waktu Pemrosesan Dekripsi : ", time1-time0, "seconds")

            is_saving = input("Apakah anda ingin menyimpan plainteks (ya/tidak) : ")

            if is_saving == 'ya':
                plaintext_filename = input("Nama file untuk plainteks : ")
                convert_string_to_file(plaintext, plaintext_filename)
                print("Penyimpanan berhasil")
        elif chosen_menu == '7':
            n = int(input("n : "))
            g = int(input("g : "))
            x = int(input("x : "))
            y = int(input("y : "))
            
            public_x, public_y, key = generateKeyDH(n, g, x, y)

            print("Kunci Publik X : ", public_x)
            print("Kunci Publik Y : ", public_y)
            print("Kunci Sesi : ", key)
        elif chosen_menu == '8':
            bits = int(input("Masukkan jumlah bit bilangan prima yang anda inginkan : "))
            prime = generateLargePrime(bits)
            print("Bilangan prima acak dengan", bits, "bit: ", prime)
        elif chosen_menu == '9':
            break
        else:
            print("Input tidak sesuai, silakan ulangi lagi!")
    
main()


