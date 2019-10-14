import sys # Import sys to be able to read arguments passed through the command line

# Read the ciphertext and save it in a variable
with open(sys.argv[1]) as c:
    cipher_text = c.read()

# Read the key and save it in a variable
with open(sys.argv[2]) as k:
    key = k.read().strip()

# Decode the ciphertext with the key and save it in a variable
decoded = ""
for i in cipher_text:
    # If the current character in the ciphertext is a letter, decode it, otherwise just add the original character
    if 'A'<=i<='Z':
        spot = key.find(i)
        decoded+=chr(ord('A')+spot)
    else:
        decoded+=i


with open(sys.argv[3], "w") as w:
    w.write(decoded)
    w.close()
