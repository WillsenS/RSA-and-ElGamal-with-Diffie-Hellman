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


main()


