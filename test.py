class DES:
    def __init__(self, key: str) -> None:
        # Convert input hexadecimal key to 64-bit binary string
        self.key = self.hex_to_bin(key)

    @staticmethod
    def hex_to_bin(hex_str) -> str:
        return bin(int(hex_str, 16))[2:].zfill(64)  # Converts hex string to 64-bit binary string

key = '9BC1546914997F6C'
des = DES(key=key)
print(des.key)