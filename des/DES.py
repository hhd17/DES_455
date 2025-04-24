from des import Mixer, Round
from des.PBox import PBox
from des.utils import left_circ_shift, int_to_bin


class DES:
    def __init__(self, key: str) -> None:
        # Convert input hexadecimal key to 64-bit binary string
        self.key = self.hex_to_bin(key)
        # Initialize permutation boxes
        self.PC_1 = PBox.des_key_initial_permutation()  # PC_1: Used to permute the key
        self.PC_2 = PBox.des_shifted_key_permutation()  # PC_2: Permutation after circular shift
        self.P_i = PBox.des_initial_permutation()  # Initial permutation of plaintext
        self.P_f = PBox.des_final_permutation()  # Final permutation after last round
        # Rounds 1, 2, 9, 16 do a 1-bit shift, rest do a 2-bit shift
        self.single_shift = {1, 2, 9, 16}
        # Pre-generate round objects and store key expansions
        self.rounds, self.key_expansions = self.generate_rounds()

    @staticmethod
    def hex_to_bin(hex_str) -> str:
        return bin(int(hex_str, 16))[2:].zfill(64)  # Converts hex string to 64-bit binary string

    @staticmethod
    def bin_to_hex(bin_str) -> str:
        return hex(int(bin_str, 2))[2:].upper().zfill(16)  # Converts 64-bit binary string to uppercase hex (16 characters)

    def encrypt(self, hex_input: str) -> tuple[str, list[str], list[str]]:
        # 1) Convert hex input to binary and apply initial permutation
        binary = self.hex_to_bin(hex_input)
        binary = self.P_i.permutate(binary)
    
        # 2) Preserve this for the round-1 split
        initial_binary = binary
    
        # 3) Prepare results list
        round_results = []
    
        # 4) Run all 16 rounds, but on idx 0 record detailed breakdown
        for idx, enc_round in enumerate(self.rounds):
            new_binary, _ = enc_round.encrypt(binary)
    
            if idx == 0:
                mixer = enc_round.mixer
                # split into L0 / R0
                L0, R0 = initial_binary[:32], initial_binary[32:]
                # expand R0 → 48 bits
                Expand = mixer.initial_permutation.permutate(R0)
                # XOR with the round key
                XOR    = int_to_bin(
                    mixer.func(int(Expand, 2), mixer.key),
                    block_size=mixer.initial_permutation.out_degree
                )
                # S-box substitution back to 32 bits
                sbox_out = ""
                step = mixer.substitution_block_size
                for i, box in enumerate(mixer.substitutions):
                    chunk = XOR[i*step:(i+1)*step]
                    res = box(chunk)
                    if not isinstance(res, str):
                        res = bin(res)[2:].zfill(4)
                    sbox_out += res
                # P-box permutation
                P_Box = mixer.final_permutation.permutate(sbox_out)
                # new left half L1 = L0 ⊕ P_Box
                L1 = int_to_bin(int(L0, 2) ^ int(P_Box, 2), block_size=32)
    
                # collect everything into a dict
                breakdown = {
                    "L0":     L0,
                    "R0":     R0,
                    "Expand": Expand,
                    "XOR":    XOR,
                    "S-Box":  sbox_out,
                    "P-Box":  P_Box,
                    "L1":     L1,
                    "Combined (pre-swap)": L1 + R0
                }
                round_results.append(breakdown)
            else:
                # all other rounds just store the 64-bit hex
                round_results.append(self.bin_to_hex(new_binary))
    
            # prepare for the next round
            binary = new_binary
    
        
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
            expanded_key = self.bin_to_hex(l + r)  # Save the pre-permutation version for visualization

            # Create mixer and round configuration
            mixer = Mixer.des_mixer(key)
            cipher = Round.with_swapper(mixer) if i != 16 else Round.without_swapper(mixer)

            rounds.append(cipher)
            key_expansions.append(expanded_key)

        return rounds, key_expansions
