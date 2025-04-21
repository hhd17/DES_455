from des import Mixer, Round
from des.PBox import PBox
from des.utils import left_circ_shift


class DES:
    def __init__(self, key: str) -> None:
        # Convert input hexadecimal key to 64-bit binary string
        self.key = self.hex_to_bin(key)
        # Initialize permutation boxes
        self.PC_1 = PBox.des_key_initial_permutation()              # PC_1: Used to permute the key
        self.PC_2 = PBox.des_shifted_key_permutation()              # PC_2: Permutation after circular shift
        self.P_i = PBox.des_initial_permutation()                   # Initial permutation of plaintext
        self.P_f = PBox.des_final_permutation()                     # Final permutation after last round
        # Rounds 1, 2, 9, 16 do a 1-bit shift, rest do a 2-bit shift
        self.single_shift = {1, 2, 9, 16}
        # Pre-generate round objects and store key expansions
        self.rounds, self.key_expansions = self.generate_rounds()

    @staticmethod
    def hex_to_bin(hex_str) -> str:
        return bin(int(hex_str, 16))[2:].zfill(64)              # Converts hex string to 64-bit binary string

    @staticmethod
    def bin_to_hex(bin_str) -> str:             
        return hex(int(bin_str, 2))[2:].upper().zfill(16)       # Converts 64-bit binary string to uppercase hex (16 characters)

    def encrypt(self, hex_input: str) -> tuple[str, list[str], list[str]]:
        # Convert hex input to binary and apply initial permutation
        binary = self.hex_to_bin(hex_input)             
        binary = self.P_i.permutate(binary)
        round_results = []

        # Perform 16 rounds of DES encryption
        for enc_round in self.rounds:
            binary, round_result = enc_round.encrypt(binary)
            round_results.append(self.bin_to_hex(binary))  # Full 64-bit block

        # Apply final permutation to the 64-bit output
        encrypted_binary = self.P_f.permutate(binary)

        return self.bin_to_hex(encrypted_binary), round_results, self.key_expansions

    def decrypt(self, hex_input: str) -> tuple[str, list[str], list[str]]:
        # Convert input hex to binary and reverse the final permutation
        binary = self.hex_to_bin(hex_input)
        binary = self.P_f.invert().permutate(binary)
        round_results = []
        
        # Perform 16 rounds in reverse order for decryption
        for dec_round in self.rounds[::-1]:  # Reverse order for decryption
            binary, round_result = dec_round.decrypt(binary)
            round_results.append(self.bin_to_hex(binary))

        # Apply inverse of the initial permutation to get plaintext
        decrypted_binary = self.P_i.invert().permutate(binary)

        return self.bin_to_hex(decrypted_binary), round_results, self.key_expansions

    def generate_rounds(self) -> tuple[list[Round], list[str]]:
        rounds = []
        key_expansions = []
        
        # Apply PC_1 permutation on the 64-bit key then split into two 28-bit halves
        self.key = self.PC_1.permutate(self.key)
        l, r = self.key[:28], self.key[28:]

        # Generate 16 subkeys and round objects
        for i in range(1, 17):

            # Decide shift amount (1 or 2 bits)
            shift = 1 if i in self.single_shift else 2

            # Perform circular left shifts on both halves
            l, r = left_circ_shift(l, shift), left_circ_shift(r, shift)

            # Apply PC_2 permutation on the combined 56-bit key to get subkey
            key = int(self.PC_2.permutate(l + r), base=2)
            expanded_key = self.bin_to_hex(l + r)   # Save the pre-permutation version for visualization
            
            # Create mixer and round configuration
            mixer = Mixer.des_mixer(key)
            cipher = Round.with_swapper(mixer) if i != 16 else Round.without_swapper(mixer)

            rounds.append(cipher)
            key_expansions.append(expanded_key)

        return rounds, key_expansions
