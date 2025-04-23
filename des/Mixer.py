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
        L0 = binary[:self.block_size // 2]
        R0 = binary[self.block_size // 2:]

        # Step 1: Expand R0 using E-table (initial permutation)
        ER = self.initial_permutation.permutate(R0)

        # Step 2: XOR with round key
        xored = int_to_bin(self.func(int(ER, 2), self.key), block_size=self.initial_permutation.out_degree)

        # Step 3: S-box substitution
        sbox_outputs = []
        sbox_result = ''
        for i in range(len(self.substitutions)):
            block = xored[i * self.substitution_block_size : (i + 1) * self.substitution_block_size]
            substituted = self.substitutions[i](block)
            substituted = bin(substituted)[2:].zfill(4) if not isinstance(substituted, str) else substituted
            sbox_outputs.append(substituted)
            sbox_result += substituted

        # Step 4: P-box permutation
        F_result = self.final_permutation.permutate(sbox_result)

        # Step 5: L1 and R1
        L1 = R0
        R1 = int_to_bin(int(L0, 2) ^ int(F_result, 2), block_size=self.block_size // 2)

        output = L1 + R1

        if verbose:
            return output, {
                "L0": L0,
                "R0": R0,
                "E(R0)": ER,
                "R0 ⊕ K1": xored,
                "S-box outputs": sbox_outputs,
                "P(S)": F_result,
                "L1": L1,
                "R1": R1,
                
            }

        return output, F_result

    def decrypt(self, binary: str, verbose=False):
        # Feistel: input is R1 + L1 (swapped)
        R1 = binary[:self.block_size // 2]
        L1 = binary[self.block_size // 2:]

        # Step 1: Expand R1
        ER = self.initial_permutation.permutate(R1)

        # Step 2: XOR with round key
        xored = int_to_bin(self.func(int(ER, 2), self.key), block_size=self.initial_permutation.out_degree)

        # Step 3: S-box substitution
        sbox_outputs = []
        sbox_result = ''
        for i in range(len(self.substitutions)):
            block = xored[i * self.substitution_block_size : (i + 1) * self.substitution_block_size]
            substituted = self.substitutions[i](block)
            substituted = bin(substituted)[2:].zfill(4) if not isinstance(substituted, str) else substituted
            sbox_outputs.append(substituted)
            sbox_result += substituted

        # Step 4: P-box permutation
        F_result = self.final_permutation.permutate(sbox_result)

        # Step 5: Recover L0 and R0
        R0 = L1
        L0 = int_to_bin(int(R1, 2) ^ int(F_result, 2), block_size=self.block_size // 2)

        output = L0 + R0

        if verbose:
            return output, {
                "R1": R1,
                "L1": L1,
                "E(R1)": ER,
                "R1 ⊕ K1": xored,
                "S-box outputs": sbox_outputs,
                "P(S)": F_result,
                "L0": L0,
                "R0": R0,
                
            }

        return output, F_result

    @staticmethod
    def des_mixer(key: int):
        # Static method to generate a DES-standard Mixer
        return Mixer(
            key=key,
            initial_permutation=PBox.des_single_round_expansion(),  # Expand 32-bit R to 48-bit
            final_permutation=PBox.des_single_round_final(),  # Permutation after S-boxes
            func=lambda a, b: a ^ b  # XOR function
        )
