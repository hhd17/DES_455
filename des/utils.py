# Convert an integer to a binary string of exactly block_size bits (padded with 0s if needed)
def int_to_bin(number: int, block_size: int = 8) -> str:
    return bin(number)[2:].zfill(block_size)[-block_size:]  # Trim or pad to exact size


# Perform a left circular shift on a binary string
def left_circ_shift(binary: str, shift: int) -> str:
    shift = shift % len(binary)  # Make sure shift isn't larger than the string length
    return binary[shift:] + binary[:shift]  # Rotate left


# Ensure a string is valid hex. if not, convert it to hex from text
def ensure_hex(s: str) -> str:
    try:
        int(s, 16)  # Check if it's valid hex
        return s.lower() if len(s) % 2 == 0 else '0' + s.lower()  # Pad with 0 if odd length
    except ValueError:
        return s.encode().hex()  # Convert plain text to hex


# Convert a hex string to text. show placeholder if invalid
def hex_to_text(hex_str: str) -> str:
    try:
        return bytes.fromhex(hex_str).decode(errors='replace')  # Decode to text
    except ValueError:
        return '[Invalid hex]'  # Return placeholder if input is not valid hex