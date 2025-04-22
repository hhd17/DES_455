from des import Mixer, NoneSwapper, Swapper


class Round:
    def __init__(self, mixer, key_expansion=None):
        self.mixer = mixer  # Handles mixing
        self.swapper = NoneSwapper()  # Default: no swap (used in last round)
        self.key_expansion = key_expansion  # Key info for logging/debug

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

    def encrypt(self, binary: str, verbose=False):
        if verbose:
            # Get detailed breakdown from mixer
            binary, step_details = self.mixer.encrypt(binary, verbose=True)
        
            # Apply swap
            swapped_binary = self.swapper.encrypt(binary)

            # Add swap result to breakdown
            step_details["after_swap"] = swapped_binary
            return swapped_binary, step_details
        else:
            # Regular encryption
            binary, round_result = self.mixer.encrypt(binary)
            swapped_binary = self.swapper.encrypt(binary)
            return swapped_binary, round_result

    def decrypt(self, binary: str, verbose=False):
        if verbose:
            # 1. Undo the swap first
            binary = self.swapper.decrypt(binary)

            # 2. Call mixer in verbose mode
            binary, step_details = self.mixer.decrypt(binary, verbose=True)

            # 3. Track final result after mixer
            step_details["after_unswap"] = binary
            return binary, step_details
        else:
            # Default silent behavior
            binary = self.swapper.decrypt(binary)
            binary, _ = self.mixer.decrypt(binary)
            return binary, binary
