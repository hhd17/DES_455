from des.utils import int_to_bin
from des.PBox import PBox
from des.SBox import SBox


class Mixer:
    def __init__(self, key: int, func=lambda a, b: a % b, block_size=64,
                 initial_permutation=None, final_permutation=None,
                 substitutions=None, substitution_block_size=6):
        self.func = func
        self.block_size = block_size
        self.initial_permutation = PBox.identity(block_size // 2) if initial_permutation is None else initial_permutation
        self.final_permutation = PBox.identity(block_size // 2) if final_permutation is None else final_permutation
        self.substitutions = SBox.des_single_round_substitutions() if substitutions is None else substitutions
        self.substitution_block_size = substitution_block_size
        self.key = key

    def encrypt(self, binary: str):
        l, r = binary[:self.block_size // 2], binary[self.block_size // 2:]
        r1 = self.initial_permutation.permutate(r)
        r2 = int_to_bin(self.func(int(r1, base=2), self.key), block_size=self.initial_permutation.out_degree)

        r3 = ''
        for i in range(len(self.substitutions)):
            block = r2[i * self.substitution_block_size: (i + 1) * self.substitution_block_size]
            substitution_result = self.substitutions[i](block)
            if not isinstance(substitution_result, str):
                substitution_result = bin(substitution_result)[2:].zfill(self.substitution_block_size)
            r3 += substitution_result

        r3 = self.final_permutation.permutate(r3)

        if not isinstance(r3, str):
            raise TypeError(f"Expected r3 to be a string, but got {type(r3)}")

        l = int_to_bin(int(l, base=2) ^ int(r3, base=2), block_size=self.block_size // 2)
        return l + r, r3

    def decrypt(self, binary: str):
        return self.encrypt(binary)

    @staticmethod
    def des_mixer(key: int):
        return Mixer(
          key=key,
          initial_permutation=PBox.des_single_round_expansion(),
          final_permutation=PBox.des_single_round_final(),
          func=lambda a, b: a % b
        )