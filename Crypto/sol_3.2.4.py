from Crypto.PublicKey import RSA
import pbp
import fractions
from math import floor

def prod(iterable):
    return reduce(lambda x, y: x*y, iterable, 1)
#src: CS461 Public Repo - Crypto

def productTree(X):
    result = [X]
    while len(X) > 1:
        X = [prod(X[i*2:(i+1)*2]) for i in range((len(X)+1)/2)]
        result.append(X)
    return result
#src: CS461 Public Repo - Crypto

def batchgcd_faster(X):
    prods = productTree(X)
    R = prods.pop()
    while prods:
        X = prods.pop()
        R = [R[int(floor(i/2))] % X[i]**2 for i in range(len(X))]
    return [fractions.gcd(r/n,n) for r,n in zip(R,X)]
#src: CS461 Public Repo - Crypto

def gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modInverse(a, m):
    g, x, y = gcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
#https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python/4801358 (modInverse and egcd)


with open('moduli.hex') as f:
    for i in f:
        moduli = [line.rstrip() for line in f]
    for i in range(len(moduli)):
        moduli[i] = int(moduli[i],16)
#src: https://stackoverflow.com/questions/19062574/read-file-into-list-and-strip-newlines

with open('3.2.4_ciphertext.enc.asc') as g:
    cipher = g.read()

priv = []
#calculate product tree, remainder tree, and corresponding GCDs in accordance to Mining Ps and Qs paper
gcds = batchgcd_faster(moduli)
#loop through all GCDs that are not 1
for i in range(len(gcds)):
    if(gcds[i]!=1):
        p = gcds[i]
        q = moduli[i]//p #calculate q from p and respective moduli
        k = modInverse(65537, (p-1)*(q-1)) #calculate private exponent from calculated primes-1 and public exponent
        priv.append(RSA.construct((long(moduli[i]), long(65537), long(k)))) #use RSA to make private keys
with open('sol_3.2.4.txt', 'w') as h:
    for m in priv:
        try:
            dec = pbp.decrypt(m, cipher) #attempt to decrypt ciphertext with all possible private keys
            h.write(dec) #write plaintext into output file
        except ValueError:
            temp = 0    #junk, ensure decrypt attempt does not throw error
