def int_to_bin(number: int, block_size: int = 8) -> str:
    return bin(number)[2:].zfill(block_size)[-block_size:]  # 0 padded binary string of exactly block_size bits


def left_circ_shift(binary: str, shift: int) -> str:
    shift = shift % len(binary)
    return binary[shift:] + binary[0: shift]


def ensure_hex(s: str) -> str:
    try:
        int(s, 16)
        return s.lower() if len(s) % 2 == 0 else '0' + s.lower()
    except ValueError:
        return s.encode().hex()


def hex_to_text(hex_str: str) -> str:
    try:
        return bytes.fromhex(hex_str).decode(errors='replace')
    except ValueError:
        return '[Invalid hex]'
