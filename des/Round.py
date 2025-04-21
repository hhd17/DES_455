from des import Mixer, NoneSwapper, Swapper


class Round:
    def __init__(self, mixer, key_expansion=None):
        self.mixer = mixer                      # Handles mixing 
        self.swapper = NoneSwapper()            # Default: no swap (used in last round)
        self.key_expansion = key_expansion      # Key info for logging/debug

    @staticmethod
    def with_swapper(mixer: Mixer, key_expansion=None):
        # Create a round with left-right swapping (used in rounds 1–15)
        temp = Round(mixer, key_expansion)
        temp.swapper = Swapper(block_size=mixer.block_size)
        return temp

    @staticmethod
    def without_swapper(mixer: Mixer, key_expansion=None):
        # Create a round without swapping (used in round 16)
        return Round(mixer, key_expansion)

    def encrypt(self, binary: str):
        # Apply mixer, then swap left and right
        binary, round_result = self.mixer.encrypt(binary)
        swapped_binary = self.swapper.encrypt(binary)
        return swapped_binary, round_result

    def decrypt(self, binary: str):
        # Undo swap, then apply mixer 
        binary = self.swapper.decrypt(binary)
        return self.mixer.encrypt(binary)