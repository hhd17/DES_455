from os import urandom

BLOCK_SIZE = 8  # DES block size is 8 bytes (64 bits)

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b)) #xoring bytes

def pad(plaintext, block_size=BLOCK_SIZE):
    padding_len = block_size - (len(plaintext) % block_size) #padding final CBC block
    padding = bytes([padding_len] * padding_len)
    return plaintext + padding

def unpad(padded_text, block_size=BLOCK_SIZE):
    padding_len = padded_text[-1]
    if padding_len < 1 or padding_len > block_size:
        raise ValueError("Invalid padding")
    if padded_text[-padding_len:] != bytes([padding_len] * padding_len): #unpadding in CBC decryption
        raise ValueError("Invalid padding")
    return padded_text[:-padding_len]

def encrypt_cbc(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)
    padded = pad(plaintext)
    ciphertext = b""
    prev_block = iv

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i+BLOCK_SIZE]
        xored = xor_bytes(block, prev_block)
        encrypted = encrypt_block(xored, key)
        ciphertext += encrypted
        prev_block = encrypted

    return iv + ciphertext  

def decrypt_cbc(ciphertext, key, decrypt_block):
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext_body = ciphertext[BLOCK_SIZE:]
    plaintext = b""
    prev_block = iv

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i+BLOCK_SIZE]
        decrypted = decrypt_block(block, key)
        xored = xor_bytes(decrypted, prev_block)
        plaintext += xored
        prev_block = block

    return unpad(plaintext)
def encrypt_cfb(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)
    ciphertext = b""
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        encrypted = encrypt_block(prev, key)
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), encrypted)
        ciphertext += cipher_block[:len(block)]
        prev = cipher_block

    return iv + ciphertext

def decrypt_cfb(ciphertext, key, encrypt_block):
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext_body = ciphertext[BLOCK_SIZE:]
    plaintext = b""
    prev = iv

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i + BLOCK_SIZE]
        encrypted = encrypt_block(prev, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), encrypted)
        plaintext += plain_block[:len(block)]
        prev = block

    return plaintext
def encrypt_ofb(plaintext, key, encrypt_block):
    iv = urandom(BLOCK_SIZE)
    output = b""
    prev = iv

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, key)
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += cipher_block[:len(block)]
        prev = keystream

    return iv + output

def decrypt_ofb(ciphertext, key, encrypt_block):
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext_body = ciphertext[BLOCK_SIZE:]
    output = b""
    prev = iv

    for i in range(0, len(ciphertext_body), BLOCK_SIZE):
        block = ciphertext_body[i:i + BLOCK_SIZE]
        keystream = encrypt_block(prev, key)
        plain_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += plain_block[:len(block)]
        prev = keystream

    return output
def encrypt_ctr(plaintext, key, encrypt_block):
    nonce = urandom(BLOCK_SIZE // 2)
    output = b""
    counter = 0

    for i in range(0, len(plaintext), BLOCK_SIZE):
        block = plaintext[i:i + BLOCK_SIZE]
        counter_bytes = counter.to_bytes(BLOCK_SIZE // 2, byteorder='big')
        keystream_input = nonce + counter_bytes
        keystream = encrypt_block(keystream_input, key)
        cipher_block = xor_bytes(block.ljust(BLOCK_SIZE, bytes([0])), keystream)
        output += cipher_block[:len(block)]
        counter += 1

    return nonce + output

def decrypt_ctr(ciphertext, key, encrypt_block):
    nonce = ciphertext[:BLOCK_SIZE // 2]
    ciphertext_body = ciphertext[BLOCK_SIZE // 2:]
    output = b""
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