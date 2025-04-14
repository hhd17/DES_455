from des import Mixer, NoneSwapper, Swapper


class Round:
    def __init__(self, mixer, key_expansion=None):
        self.mixer = mixer
        self.swapper = NoneSwapper()
        self.key_expansion = key_expansion

    @staticmethod
    def with_swapper(mixer: Mixer, key_expansion=None):
        temp = Round(mixer, key_expansion)
        temp.swapper = Swapper(block_size=mixer.block_size)
        return temp

    @staticmethod
    def without_swapper(mixer: Mixer, key_expansion=None):
        return Round(mixer, key_expansion)

    def encrypt(self, binary: str):
        binary, round_result = self.mixer.encrypt(binary)
        swapped_binary = self.swapper.encrypt(binary)
        return swapped_binary, round_result

    def decrypt(self, binary: str):
        binary = self.swapper.decrypt(binary)
        return self.mixer.encrypt(binary)
