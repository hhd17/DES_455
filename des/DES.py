from des import Mixer, Round
from des.PBox import PBox
from des.utils import left_circ_shift


class DES:
    def __init__(self, key: str) -> None:
        # Convert hex key to binary
        self.key = self.hex_to_bin(key)
        self.PC_1 = PBox.des_key_initial_permutation()
        self.PC_2 = PBox.des_shifted_key_permutation()
        self.P_i = PBox.des_initial_permutation()
        self.P_f = PBox.des_final_permutation()
        self.single_shift = {1, 2, 9, 16}
        self.rounds, self.key_expansions = self.generate_rounds()

    @staticmethod
    def hex_to_bin(hex_str) -> str:
        return bin(int(hex_str, 16))[2:].zfill(64)

    @staticmethod
    def bin_to_hex(bin_str) -> str:
        return hex(int(bin_str, 2))[2:].upper().zfill(16)

    def encrypt(self, hex_input: str) -> tuple[str, list[str], list[str]]:
        binary = self.hex_to_bin(hex_input)
        binary = self.P_i.permutate(binary)
        round_results = []

        for enc_round in self.rounds:
            binary, round_result = enc_round.encrypt(binary)
            round_results.append(self.bin_to_hex(binary))  # Full 64-bit block

        encrypted_binary = self.P_f.permutate(binary)
        return self.bin_to_hex(encrypted_binary), round_results, self.key_expansions

    def decrypt(self, hex_input: str) -> tuple[str, list[str], list[str]]:
        binary = self.hex_to_bin(hex_input)
        binary = self.P_f.invert().permutate(binary)
        round_results = []

        for dec_round in self.rounds[::-1]:  # Reverse order for decryption
            binary, round_result = dec_round.decrypt(binary)
            round_results.append(self.bin_to_hex(binary))

        decrypted_binary = self.P_i.invert().permutate(binary)
        return self.bin_to_hex(decrypted_binary), round_results, self.key_expansions

    def generate_rounds(self) -> tuple[list[Round], list[str]]:
        rounds = []
        key_expansions = []

        self.key = self.PC_1.permutate(self.key)
        l, r = self.key[:28], self.key[28:]

        for i in range(1, 17):
            shift = 1 if i in self.single_shift else 2
            l, r = left_circ_shift(l, shift), left_circ_shift(r, shift)
            key = int(self.PC_2.permutate(l + r), base=2)
            expanded_key = self.bin_to_hex(l + r)

            mixer = Mixer.des_mixer(key)
            cipher = Round.with_swapper(mixer) if i != 16 else Round.without_swapper(mixer)

            rounds.append(cipher)
            key_expansions.append(expanded_key)

        return rounds, key_expansions
