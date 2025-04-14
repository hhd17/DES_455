def int_to_bin(number: int, block_size: int = 8) -> str:
    return bin(number)[2:].zfill(block_size)[-block_size:]  # 0 padded binary string of exactly block_size bits


def left_circ_shift(binary: str, shift: int) -> str:
    shift = shift % len(binary)
    return binary[shift:] + binary[0: shift]
