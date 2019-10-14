import sys # Import sys to be able to read arguments passed through the command line
import hashlib # Import the hashlib library to generate the SHA-256 hash

with open(sys.argv[1]) as o:
    input_string = o.read().strip()
    input_hash = hashlib.sha256(input_string).hexdigest()
    input_int = int(input_hash,16)
    input_bin = format(input_int, '0256b')

with open(sys.argv[2]) as p:
    pert_string = p.read().strip()
    pert_hash = hashlib.sha256(pert_string).hexdigest()
    pert_int = int(pert_hash,16)
    pert_bin = format(pert_int, '0256b')

hamming_dist = 0
for i in range (0,256):
    if input_bin[i] != pert_bin[i]:
        hamming_dist+=1

hamming_str = hex(hamming_dist)[2:]

#print(input_hash)
#print(input_bin)
#print(pert_hash)
#print(pert_bin)
#print(hamming_dist)
#print(hamming_str)

with open(sys.argv[3], "w") as w:
    w.write(hamming_str)
    w.close()
