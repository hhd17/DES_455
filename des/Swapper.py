class Swapper:
    def __init__(self, block_size=64) -> None:
        self.block_size = block_size  

    def encrypt(self, binary: str) -> str:
        # Split into left and right halves, then swap them
        l, r = binary[0: self.block_size // 2], binary[self.block_size // 2:]
        return r + l  # Return swapped string

    def decrypt(self, binary: str) -> str:
        # Same as encrypt (swapping again restores original)
        return self.encrypt(binary)