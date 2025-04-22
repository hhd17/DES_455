from os import urandom

# DES block size in bytes 
BLOCK_SIZE = 8


# XOR two byte strings of equal length
def xor_bytes(a, b):
    # Performs XOR operation byte by byte
    return bytes(x ^ y for x, y in zip(a, b))


# Apply PKCS-style padding to the input data
def pad(plaintext, block_size=BLOCK_SIZE):
    # Calculate how many padding bytes are needed
    padding_len = block_size - (len(plaintext) % block_size)
    # Create padding where each byte is equal to padding length 
    padding = bytes([padding_len] * padding_len)
    # Append padding to plaintext
    return plaintext + padding


# Remove padding from decrypted data
def unpad(padded_text, block_size=BLOCK_SIZE):
    try:
        padding_len = padded_text[-1]  # Last byte indicates padding length
        if padding_len < 1 or padding_len > block_size:
            raise ValueError('Invalid padding')
        if padded_text[-padding_len:] != bytes([padding_len] * padding_len):
            raise ValueError('Invalid padding')
        return padded_text[:-padding_len]
    except Exception:
        # If padding is invalid, return data unchanged 
        return padded_text



# CBC (Cipher Block Chaining) MODE

def encrypt_cbc(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)            # Generate random IV (Initialization Vector)
    padded = pad(plaintext)             # Pad plaintext to match block size
    ciphertext = b''
    prev_block = iv                     # Initial chaining block is the IV

    # Process each 8-byte block
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = xor_bytes(block, prev_block)         # XOR plaintext block with previous ciphertext
        encrypted = encrypt_block(xored, key)        # Encrypt result
        ciphertext += encrypted                      # Append to ciphertext
        prev_block = encrypted                       # Update chaining block

    return ciphertext, iv                           


def decrypt_cbc(ciphertext, key, decrypt_block, iv):
    decrypted = b''
    prev_block = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        decrypted_block = decrypt_block(block, key)
        decrypted += xor_bytes(decrypted_block, prev_block)
        prev_block = block

    return unpad(decrypted)


 
# CFB (Cipher Feedback) MODE
 
def encrypt_cfb(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)                         # Generate IV
    ciphertext = b''
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        encrypted = encrypt_block(prev, key)         # Encrypt previous ciphertext (or IV)
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), encrypted)
        ciphertext += cipher_block[:len(block)]      # Trim padding for last block
        prev = cipher_block                          # Update feedback register

    return ciphertext, iv


def decrypt_cfb(ciphertext, key, encrypt_block, iv):
    plaintext = b''
    prev = iv

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        encrypted = encrypt_block(prev, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), encrypted)
        plaintext += plain_block[:len(block)]
        prev = block

    return plaintext


 
# OFB (Output Feedback) MODE
 
def encrypt_ofb(plaintext, key, encrypt_block):
    nonce = urandom(BLOCK_SIZE)
    output = b''
    prev = nonce

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, key)                        # Encrypt previous output
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += cipher_block[:len(block)]
        prev = keystream                                            # Update keystream

    return output, nonce


def decrypt_ofb(ciphertext, key, encrypt_block, nonce):
    # Decryption is identical to encryption in OFB mode
    output = b''
    prev = nonce

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += plain_block[:len(block)]
        prev = keystream

    return output


 
# CTR (Counter) MODE
 
def encrypt_ctr(plaintext, key, encrypt_block):

    # Generate a full 8-byte (64-bit) random counter
    initial_counter = int.from_bytes(urandom(BLOCK_SIZE), byteorder='big')
    ciphertext = b''

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]

        # Convert counter to bytes
        counter_bytes = (initial_counter + i // BLOCK_SIZE).to_bytes(BLOCK_SIZE, byteorder='big')

        # Encrypt counter to get keystream
        keystream = encrypt_block(counter_bytes, key)

        # XOR with padded block and cut to actual size
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        ciphertext += cipher_block[:len(block)]

    return ciphertext, initial_counter.to_bytes(BLOCK_SIZE, byteorder='big')  # Return cipher + raw counter


def decrypt_ctr(ciphertext, key, encrypt_block, initial_counter_bytes):
    plaintext = b''
    initial_counter = int.from_bytes(initial_counter_bytes, byteorder='big')

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]

        # Reconstruct counter value for this block
        counter_bytes = (initial_counter + i // BLOCK_SIZE).to_bytes(BLOCK_SIZE, byteorder='big')

        # Generate keystream from encrypted counter
        keystream = encrypt_block(counter_bytes, key)

        # XOR ciphertext block with keystream
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        plaintext += plain_block[:len(block)]

    return plaintext