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

def RSAPrivateKey(e,Tn):
    d = 1
    while True:
        if ((d * e) % Tn == 1):
            return d
        else:
            d += 1

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
    while True:
        p = int(input("masukkan p: "))
        q = int(input("masukkan q: "))
        if (isPrime(p) and isPrime(q)):
            break
        else:
            print("p dan q harus prima!")
    n = int(p) * int(q)
    Tn = toitentEuler(p,q)
    while True:
        Pkey = int(input("input public key: "))
        if isCoprime(Pkey,Tn):
            break
        else:
            print("Harus koprima dengan " + str(Tn))

    print("############ THIS IS BOB ############")
    plaintext = input("Masukkan Plaintext: ")
    enc = RSAEncrypt(plaintext,Pkey,n)
    print("hasil: ")
    print (enc)

    print("############ THIS IS ALICE ############")
    d = RSAPrivateKey(Pkey,Tn)
    dec = RSADecrypt(enc,d,n)
    print(dec)


main()


