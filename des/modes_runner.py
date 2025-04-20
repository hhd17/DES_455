from des import DES
from des import modes


def run_des(action: str, mode: str, hex_message: str, hex_key: str):
    des = DES(key=hex_key)
    raw_key_bytes = hex_key.encode()

    def encrypt_block(block: bytes, _k: bytes):
        return bytes.fromhex(des.encrypt(block.hex())[0])

    def decrypt_block(block: bytes, _k: bytes):
        return bytes.fromhex(des.decrypt(block.hex())[0])

    from des.modes import pad, unpad, BLOCK_SIZE

    if mode == 'ECB':
        if action == 'encrypt':
            msg_bytes = bytes.fromhex(hex_message)
            padded = pad(msg_bytes)
            result_hex, rounds, keys = des.encrypt(padded.hex())
            return result_hex, rounds, keys

        else:
            decrypted_hex, rounds, keys = des.decrypt(hex_message)
            decrypted_bytes = bytes.fromhex(decrypted_hex)
            try:
                unpadded = unpad(decrypted_bytes)
            except Exception:
                unpadded = decrypted_bytes
            return unpadded.hex(), rounds, keys

    msg_bytes = bytes.fromhex(hex_message)

    if mode == 'CBC':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_cbc(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_cbc(msg_bytes, raw_key_bytes, decrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    if mode == 'CFB':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_cfb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_cfb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    if mode == 'OFB':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_ofb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_ofb(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    if mode == 'CTR':
        if action == 'encrypt':
            cipher_bytes = modes.encrypt_ctr(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.encrypt(msg_bytes[:BLOCK_SIZE].hex())
            return cipher_bytes.hex(), aux_rounds[1], aux_rounds[2]
        else:
            plain_bytes = modes.decrypt_ctr(msg_bytes, raw_key_bytes, encrypt_block)
            aux_rounds = des.decrypt(msg_bytes[BLOCK_SIZE:BLOCK_SIZE * 2].hex())
            return plain_bytes.hex(), aux_rounds[1], aux_rounds[2]

    raise ValueError(f'Unsupported mode {mode}')
