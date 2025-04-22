from des import DES 
from des import modes


def run_des(action: str, mode: str, hex_message: str, hex_key: str, extra: str = None):
    # Initialize DES with  provided key
    des = DES(key=hex_key)

    # Convert hex key to bytes for compatibility with mode functions
    raw_key_bytes = hex_key.encode()
    
    # Encrypt a single 8-byte block
    def encrypt_block(block: bytes, _k: bytes):
        return bytes.fromhex(des.encrypt(block.hex())[0])

    # Decrypt a single 8-byte block
    def decrypt_block(block: bytes, _k: bytes):
        return bytes.fromhex(des.decrypt(block.hex())[0])

    from des.modes import pad, unpad, BLOCK_SIZE

    # === ECB (Electronic Code Book) Mode ===
    if mode == 'ECB':
        if action == 'encrypt':
            # Pad input data and divide it into 8-byte blocks
            msg_bytes = pad(bytes.fromhex(hex_message))
            cipher_bytes = b''

            # Encrypt each block independently
            for i in range(0, len(msg_bytes), BLOCK_SIZE):
                block = msg_bytes[i:i + BLOCK_SIZE]
                cipher_bytes += encrypt_block(block, raw_key_bytes)

            # Log one block's round output for visualization
            _, rounds, keys = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), rounds, keys

        else:  # Decryption
            msg_bytes = bytes.fromhex(hex_message)
            plain_padded = b''

            # Decrypt each 8-byte block
            for i in range(0, len(msg_bytes), BLOCK_SIZE):
                block = msg_bytes[i:i + BLOCK_SIZE]
                plain_padded += decrypt_block(block, raw_key_bytes)

            # Remove padding after full decryption
            plain_bytes = unpad(plain_padded)

            # Log one block's round decryption process
            _, rounds, keys = des.decrypt(msg_bytes[:BLOCK_SIZE].hex())
            return plain_bytes.hex(), rounds, keys

    # Convert input message to bytes for all other modes
    msg_bytes = bytes.fromhex(hex_message)

    # === CBC (Cipher Block Chaining) Mode ===
    if mode == 'CBC':
        if action == 'encrypt':
            # Encrypt using CBC: XOR with previous block and encrypt
            cipher_bytes, iv = modes.encrypt_cbc(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())                      # Log 1st block
            return cipher_bytes.hex(),iv.hex(), aux_rounds[1], aux_rounds[2]
        else:
            # Decrypt using CBC: decrypt block and XOR with previous ciphertext
            iv = bytes.fromhex(extra) if extra else None
            plain_bytes = modes.decrypt_cbc(msg_bytes, raw_key_bytes, decrypt_block, iv)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    # === CFB (Cipher Feedback) Mode ===
    if mode == 'CFB':
        if action == 'encrypt':
            # Encrypt using CFB: encrypt IV, then XOR with plaintext
            cipher_bytes, iv = modes.encrypt_cfb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(),iv.hex(), aux_rounds[1], aux_rounds[2]
        else:
            # Decrypt using CFB: encrypt IV, then XOR with ciphertext
            iv = bytes.fromhex(extra) if extra else None
            plain_bytes = modes.decrypt_cfb(msg_bytes, raw_key_bytes, encrypt_block, iv)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    # === OFB (Output Feedback) Mode ===
    if mode == 'OFB':
        if action == 'encrypt':
            # Encrypt using OFB: encrypt feedback, then XOR with plaintext
            cipher_bytes, nonce = modes.encrypt_ofb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(),nonce.hex(), aux_rounds[1], aux_rounds[2]
        else:
            # Decrypt using OFB: same operation as encryption
            nonce = bytes.fromhex(extra) if extra else None
            plain_bytes = modes.decrypt_ofb(msg_bytes, raw_key_bytes, encrypt_block, nonce)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    # === CTR (Counter) Mode ===
    if mode == 'CTR':
        if action == 'encrypt':
            # Encrypt using CTR: encrypt counter, then XOR with plaintext
            cipher_bytes, counter = modes.encrypt_ctr(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(),counter.hex(), aux_rounds[1], aux_rounds[2]
        else:
            # Decrypt using CTR: same operation as encryption
            counter = bytes.fromhex(extra) if extra else None
            plain_bytes = modes.decrypt_ctr(msg_bytes, raw_key_bytes, encrypt_block, counter)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    # Raise an error for unsupported modes
    raise ValueError(f'Unsupported mode {mode}')