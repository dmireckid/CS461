import urllib2

# This function will make a request to the specified URL and return the HTTP status
def get_status(u):
    req = urllib2.Request(u)
    try:
        f = urllib2.urlopen(req)
        return f.code
    except urllib2.HTTPError, e:
        return e.code

# This function will read the given message and strip the padding
def strip_padding(msg):
    padlen = 17 - ord(msg[-1])
    if padlen > 16 or padlen < 1:
        return True, None
    if msg[-padlen:] != ''.join(chr(i) for i in range(16,16-padlen,-1)):
        return True, None
    return False, msg[:-padlen]

# Read the file containing our ciphertext hex string and save the ciphertext in original_cipher
with open('3.2.3_ciphertext.hex') as f:
    original_cipher = f.read().strip()

# Get the number of 16-byte blocks that we need to decode
blocks_to_crack=len(original_cipher)/32-1

# Initialize the plaintext we'll work with
plaintext = ""

# For each block of 16 bytes, split them up with their respective decode block to figure out each substring of the plaintext
for i in range(blocks_to_crack):
    current_cipher = original_cipher
    new_cipher = current_cipher[len(current_cipher)-32*(i+2):len(current_cipher)-32*i]
    # For each hex substring, go through each character and figure out what the proper guess is
    for c in range(16):
        # Retrieve the hex string of the current position we're guessing
        curr_hex = new_cipher[len(new_cipher)-32-2*c-2:len(new_cipher)-32-2*c]

        # Go through all the possible character values and XOR it with the original ciphertext character and the padding of value 0x10
        for v in range(256):
            guess_char = int(curr_hex,16)^v^16
            guess_hex = hex(guess_char)[2:]
            # Make sure the new hex string is two hex characters long
            if len(guess_hex) == 1:
                guess_hex = '0'+guess_hex
            # Check to see if the modified ciphertext creates correct padding, and if it does, keep its current character
            new_cipher = new_cipher[:len(new_cipher)-32-2*c-2]+guess_hex+new_cipher[len(new_cipher)-32-2*c:]
            url = "http://cs461-mp3.sprai.org:8081/mp3/mirecki2/?"+new_cipher
            status = get_status(url)
            if status==404:
                plaintext = chr(v)+plaintext
                break

        # Change the already-modified characters so that their padding properly correlates to the next character we're guessing
        for change in range(c+1):
            curr_hex = new_cipher[len(new_cipher)-32-2*(c-change)-2:len(new_cipher)-32-2*(c-change)]
            curr_char = int(curr_hex,16)^(16-change)^(15-change)
            new_hex = hex(curr_char)[2:]
            # Make sure the new hex string is two hex characters long
            if len(new_hex) == 1:
                new_hex = '0'+new_hex
            new_cipher = new_cipher[:len(new_cipher)-32-2*(c-change)-2]+new_hex+new_cipher[len(new_cipher)-32-2*(c-change):]

# Properly strip the plaintext of any additional padding
plaintext = strip_padding(plaintext)[1]
plaintext = plaintext.strip("\n")
print(plaintext)

# Save the cleaned-up plaintext in the sol_3.2.3.txt file
with open('sol_3.2.3.txt', 'w') as w:
    w.write(plaintext)
    w.close()
