import sys # Import sys to be able to read arguments passed through the command line

with open(sys.argv[1]) as s:
    input_string = s.read().strip()

#input_string = "Hello world!"
#input_string = "I am Groot."


# WHA algorithm
outHash = 0
mask = 0x3fffffff
for i in input_string:
    char_int = ord(i)
    intermediate_value = ((char_int^0xCC)<<24) | (((char_int^0x33)<<16)) | ((char_int^0xAA)<<8) | (char_int^0x55)
    outHash = (outHash & mask) + (intermediate_value & mask)

outHash_hex = (hex(outHash)[2:]).strip('L')
print(outHash_hex)


with open(sys.argv[2], "w") as w:
    w.write(outHash_hex)
    w.close()
