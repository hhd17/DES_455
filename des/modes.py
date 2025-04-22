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
    iv = urandom(BLOCK_SIZE)  # Generate random IV (Initialization Vector)
    padded = pad(plaintext)  # Pad plaintext to match block size
    ciphertext = b''
    prev_block = iv  # Initial chaining block is the IV

    # Process each 8-byte block
    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]
        xored = xor_bytes(block, prev_block)  # XOR plaintext block with previous ciphertext
        encrypted = encrypt_block(xored, key)  # Encrypt result
        ciphertext += encrypted  # Append to ciphertext
        prev_block = encrypted  # Update chaining block

    return iv + ciphertext  # Prepend IV to ciphertext


def decrypt_cbc(ciphertext, key, decrypt_block):
    iv = ciphertext[:BLOCK_SIZE]  # Extract IV
    ciphertext_body = ciphertext[BLOCK_SIZE:]  # Remaining ciphertext
    plaintext = b''
    prev_block = iv

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i + BLOCK_SIZE]
        decrypted = decrypt_block(block, key)  # Decrypt current ciphertext block
        xored = xor_bytes(decrypted, prev_block)  # XOR with previous ciphertext block (or IV)
        plaintext += xored
        prev_block = block

    return unpad(plaintext)


# CFB (Cipher Feedback) MODE

def encrypt_cfb(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)  # Generate IV
    ciphertext = b''
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        encrypted = encrypt_block(prev, key)  # Encrypt previous ciphertext (or IV)
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), encrypted)
        ciphertext += cipher_block[:len(block)]  # Trim padding for last block
        prev = cipher_block  # Update feedback register

    return iv + ciphertext


def decrypt_cfb(ciphertext, key, encrypt_block):
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext_body = ciphertext[BLOCK_SIZE:]
    plaintext = b''
    prev = iv

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i + BLOCK_SIZE]
        encrypted = encrypt_block(prev, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), encrypted)
        plaintext += plain_block[:len(block)]
        prev = block

    return plaintext


# OFB (Output Feedback) MODE

def encrypt_ofb(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)
    output = b''
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, key)  # Encrypt previous output
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += cipher_block[:len(block)]
        prev = keystream  # Update keystream

    return iv + output


def decrypt_ofb(ciphertext, key, encrypt_block):
    # Decryption is identical to encryption in OFB mode
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext_body = ciphertext[BLOCK_SIZE:]
    output = b''
    prev = iv

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += plain_block[:len(block)]
        prev = keystream

    return output


# CTR (Counter) MODE

def encrypt_ctr(plaintext, key, encrypt_block):
    nonce = urandom(BLOCK_SIZE // 2)  # Use half the block size as a nonce
    output = b''
    counter = 0

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        counter_bytes = counter.to_bytes(BLOCK_SIZE // 2, byteorder='big')  # Convert counter to bytes
        keystream_input = nonce + counter_bytes  # Concatenate nonce + counter
        keystream = encrypt_block(keystream_input, key)  # Encrypt to get keystream
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += cipher_block[:len(block)]
        counter += 1

    return nonce + output


def decrypt_ctr(ciphertext, key, encrypt_block):
    # CTR decryption = encryption
    nonce = ciphertext[:BLOCK_SIZE // 2]
    ciphertext_body = ciphertext[BLOCK_SIZE // 2:]
    output = b''
    counter = 0

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i + BLOCK_SIZE]
        counter_bytes = counter.to_bytes(BLOCK_SIZE // 2, byteorder='big')
        keystream_input = nonce + counter_bytes
        keystream = encrypt_block(keystream_input, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += plain_block[:len(block)]
        counter += 1

    return output
