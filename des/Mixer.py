from des.PBox import PBox
from des.SBox import SBox
from des.utils import int_to_bin


class Mixer:
    def __init__(
            self, key: int, func=lambda a, b: a ^ b, block_size=64, initial_permutation=None, final_permutation=None,
            substitutions=None, substitution_block_size=6
    ):
        # Function to combine right half and key 
        self.func = func

        # Size of input block 
        self.block_size = block_size

        # Expansion permutation applied before XORing with key
        self.initial_permutation = PBox.identity(block_size // 2) if initial_permutation is None else initial_permutation

        # Permutation applied after substitution step
        self.final_permutation = PBox.identity(block_size // 2) if final_permutation is None else final_permutation

        # S-boxes used for substitution 
        self.substitutions = SBox.des_single_round_substitutions() if substitutions is None else substitutions

        # Size of each input block to an S-box 
        self.substitution_block_size = substitution_block_size

        # Subkey used in the current round
        self.key = key

    def encrypt(self, binary: str):
        # Split input into left and right halves (32 bits each)
        l, r = binary[:self.block_size // 2], binary[self.block_size // 2:]

        # Apply initial permutation 
        r1 = self.initial_permutation.permutate(r)

        # XOR permuted right half with round key
        r2 = int_to_bin(self.func(int(r1, base=2), self.key), block_size=self.initial_permutation.out_degree)

        # Apply S-box substitution
        r3 = ''
        for i in range(len(self.substitutions)):
            block = r2[i * self.substitution_block_size: (i + 1) * self.substitution_block_size]
            substitution_result = self.substitutions[i](block)

            # Make sure substitution result is in 4-bit binary string format
            if not isinstance(substitution_result, str):
                substitution_result = bin(substitution_result)[2:].zfill(4)
            r3 += substitution_result

        # Apply final permutation to substituted data
        r3 = self.final_permutation.permutate(r3)

        # Type check to avoid silent errors
        if not isinstance(r3, str):
            raise TypeError(f'Expected r3 to be a string, but got {type(r3)}')

        # XOR left half with output from final permutation to get new left
        l = int_to_bin(int(l, base=2) ^ int(r3, base=2), block_size=self.block_size // 2)

        # Return new 64-bit block and intermediate value r3 for logging
        return l + r, r3

    def decrypt(self, binary: str):
        # Encryption and decryption use the same structure but keys are reversed
        return self.encrypt(binary)

    @staticmethod
    def des_mixer(key: int):
        # Static method to generate a DES-standard Mixer
        return Mixer(
            key=key,
            initial_permutation=PBox.des_single_round_expansion(),  # Expand 32-bit R to 48-bit
            final_permutation=PBox.des_single_round_final(),  # Permutation after S-boxes
            func=lambda a, b: a ^ b  # XOR function
        )
