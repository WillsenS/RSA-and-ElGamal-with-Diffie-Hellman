from Crypto.Util import number
from math import gcd as bltin_gcd

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

def main():
    print("############ THIS IS ALICE ############")
    # while True:
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
    plaintext = input("Masukkan Plaintext: ")
    enc = RSAEncrypt(plaintext,Pkey,n)
    print("Encrypted: " + "".join(str(enc)))
    # print("hasil: ")
    # print (enc)

    print("############ THIS IS ALICE ############")
    d = generateRSAPrivateKey(Pkey,Tn)
    dec = RSADecrypt(enc,d,n)
    print("Decryption: "+ dec)


main()


