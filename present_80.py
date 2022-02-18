import time


class PRESENT_80:
    def __init__(self, rnd=32):
        # parameters
        self.ROUND = rnd
        self.Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
        self.Pbox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
                     4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
                     8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
                     12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

    # create a round-key array for each round
    def generate_round_key(self, k):
        """
        :param k: Original Key
        :return: Generate 32 round keys follows the pattern below
            1. At round i the 64-bit round key consists of the 64 leftmost bits of the current contents of key.
            2. Rotated 61 bits to the left
            3. Pass the left-most four bits through the present S-box
            4. round number i XOR with bits 19,18,17,16,15 of key
        """
        round_key = []
        for i in range(1, self.ROUND + 1):
            # At round i the 64-bit round key consists of the 64 leftmost bits of the current contents of key.
            round_key.append(k >> 16)
            # print('0x' + hex(round key[i-1])[2:].zfill(16))
            # Rotated 61 bits to the left
            k = ((k & (2 ** 19 - 1)) << 61) + (k >> 19)
            # Pass the left-most four bits through the present S-box
            k = ((self.Sbox[k >> 76] << 76) + (k & (2 ** 76 - 1)))
            # round number i XOR with bits 19,18,17,16,15 of key
            k ^= i << 15
        return round_key

    @staticmethod
    def add_round_key(s, k):
        """
        :param s: round state bit
        :param k: round key bit
        :return: s XOR k
        """
        return s ^ k

    def s_box_layer(self, text):
        """
        :param text: a hexadecimal number represent 4 bit binary number
        :return: notation to the hexadecimal number regards to the given Sbox table index number.
        """
        tmp_text = 0
        for i in range(16):
            tmp_text += self.Sbox[(text >> (i * 4) & 0xf)] << (i * 4)
        return tmp_text

    def p_layer(self, text):
        """
        :param text: the leftmost 64 of round state
        :return: Bit i of state is moved to bit position of Pbox(i)
        """
        tmp_text = 0
        for i in range(64):
            tmp_text += ((text >> i) & 0x01) << self.Pbox[i]
        return tmp_text

    @staticmethod
    def int2hex(i):
        return hex(i)[2:].zfill(16)

    @staticmethod
    def hex2int(h):
        return int.from_bytes(bytes.fromhex(h), byteorder='big')

    def encrypt(self, text, k):
        """
        :param text: Original plaintext
        :param k: Original Key
        :return: Ciphertext
        run the pattern below of 32 - 1 rounds:
            1. add the round key
            2. notate the 16 4-bit state number as Sbox table
            3. run the permutation
         *the last round add the round key only
        """
        round_key = self.generate_round_key(self.hex2int(k))
        state_text = self.hex2int(text)
        for i in range(self.ROUND-1):
            # add the round key
            state_text = self.add_round_key(state_text, round_key[i])
            # SBox layer
            state_text = self.s_box_layer(state_text)
            # PBox layer
            state_text = self.p_layer(state_text)
            # print(f"Round {i+1} output: {'0x'+ hex(state_text)[2:].zfill(16)}")
        # the last round of state
        output = self.add_round_key(state_text, round_key[-1])
        return self.int2hex(output)


if __name__ == '__main__':
    plaintext = "0000000000000000"
    key = "FFFFFFFFFFFFFFFFFFFF"
    start_time = time.perf_counter()
    present = PRESENT_80()
    ciphertext = present.encrypt(plaintext, key)
    end_time = time.perf_counter()
    print(f"Plaintext: {plaintext}")
    print(f"Key: {key}")
    print(f"Ciphertext: {ciphertext.upper()}")
    print(f"Time used: {end_time-start_time}")
