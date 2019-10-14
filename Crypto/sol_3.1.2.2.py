import sys # Import sys to be able to read arguments passed through the command line
from Crypto.Cipher import AES # Import the AES module from the Crypto library

with open(sys.argv[1]) as c:
    cipher_str = c.read().strip()
    cipher_bin = cipher_str.decode('hex')

with open(sys.argv[2]) as k:
    key_str = k.read().strip()
    key = key_str.decode('hex')

with open(sys.argv[3]) as v:
    iv_str = v.read().strip()
    iv = iv_str.decode('hex')

cipher = AES.new(key, AES.MODE_CBC, iv)

decoded = cipher.decrypt(cipher_bin)
with open(sys.argv[4], "w") as w:
    w.write(decoded)
    w.close()
