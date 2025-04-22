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

    def encrypt(self, binary: str, verbose=False):
        # Split input into left and right halves
        l = binary[:self.block_size // 2]
        r = binary[self.block_size // 2:]

        # Step 1: Initial permutation of right half
        r1 = self.initial_permutation.permutate(r)

        # Step 2: XOR right half with round key
        r2 = int_to_bin(
           self.func(int(r1, base=2), self.key),
          block_size=self.initial_permutation.out_degree
        )

        # Step 3: S-box substitution
        r3 = ''
        sbox_outputs = []
        for i in range(len(self.substitutions)):
            block = r2[i * self.substitution_block_size : (i + 1) * self.substitution_block_size]
            substitution_result = self.substitutions[i](block)

            # Format result as 4-bit binary string
            if not isinstance(substitution_result, str):
                substitution_result = bin(substitution_result)[2:].zfill(4)

            sbox_outputs.append(substitution_result)
            r3 += substitution_result

        # Step 4: P-box permutation
        r4 = self.final_permutation.permutate(r3)

        if not isinstance(r4, str):
            raise TypeError(f'Expected r4 to be a string, but got {type(r4)}')

        # Step 5: XOR with left half to get new right
        new_r = int_to_bin(int(l, base=2) ^ int(r4, base=2), block_size=self.block_size // 2)

        # Step 6: Concatenate old right and new right (as L and R are swapped)
        new_block = r + new_r

        # If verbose mode is on, return a detailed breakdown
        if verbose:
            return new_block, {
                "left": l,
                "right": r,
                "permuted_right": r1,
                "xored_with_key": r2,
                "sbox_outputs": sbox_outputs,
                "pbox_output": r4,
                "new_right": new_r,
                "final_block": new_block
            }

        return new_block, r4

    def decrypt(self, binary: str,verbose=False):
        # Encryption and decryption use the same structure but keys are reversed
        return self.encrypt(binary,verbose=verbose)

    @staticmethod
    def des_mixer(key: int):
        # Static method to generate a DES-standard Mixer
        return Mixer(
            key=key,
            initial_permutation=PBox.des_single_round_expansion(),  # Expand 32-bit R to 48-bit
            final_permutation=PBox.des_single_round_final(),  # Permutation after S-boxes
            func=lambda a, b: a ^ b  # XOR function
        )
