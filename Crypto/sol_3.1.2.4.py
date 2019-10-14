import sys # Import sys to be able to read arguments passed through the command line
import math

with open(sys.argv[1]) as c:
    cipher_hex = c.read().strip()
    cipher_int = int(cipher_hex,16)

with open(sys.argv[2]) as k:
    key_hex = k.read().strip()
    key_int = int(key_hex,16)

with open(sys.argv[3]) as m:
    modulo_hex = m.read().strip()
    modulo_int = int(modulo_hex,16)

decoded_int = pow(cipher_int, key_int, modulo_int)
decoded_hex = (hex(decoded_int)[2:]).strip('L')

with open(sys.argv[4], "w") as w:
    w.write(decoded_hex)
    w.close()
