import time


class AES_128:
    def __init__(self, rnd=10, hm=32):
        self.name = 'aes128'
        self.key = '0f1571c947d9e8590cb7add6af7f6798'   # default key
        self.hex_num = hm
        self.ROUND = rnd
        self.Rcon = [
            [0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00],
            [0x1B, 0x00, 0x00, 0x00],
            [0x36, 0x00, 0x00, 0x00]]

        self.Sbox = [
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]]

    # Plaintext Padding
    @staticmethod
    def padding_plaintext(txt):
        pad_txt = []
        while len(txt) > 16:
            pad_txt.append(int.from_bytes(txt[:16].encode(), byteorder='big'))
            txt = txt[16:]
        if len(txt) > 0:
            pad_txt.append(int.from_bytes(txt.ljust(16, '\n').encode(), byteorder='big'))
        return pad_txt

    # Round Key generator
    def regulate_keyword(self, k):
        """
        :param k: Raw Key
        :return: A 4 x 4 keyword matrix with type of integer
        split the raw key into 4 x 4 bytes of matrix
        """
        # set a boundary for the raw key
        if len(k) > 32:
            raise f"There are {len(k) - 32} extra bytes in the Keyword"
        elif len(k) < 32:
            raise f"There are {len(k) - 32} missing bytes in the Keyword"
        return [[self.str_2_int(k[0:2]), self.str_2_int(k[2:4]),
                 self.str_2_int(k[4:6]), self.str_2_int(k[6:8])],
                [self.str_2_int(k[8:10]), self.str_2_int(k[10:12]),
                 self.str_2_int(k[12:14]), self.str_2_int(k[14:16])],
                [self.str_2_int(k[16:18]), self.str_2_int(k[18:20]),
                 self.str_2_int(k[20:22]), self.str_2_int(k[22:24])],
                [self.str_2_int(k[24:26]), self.str_2_int(k[26:28]),
                 self.str_2_int(k[28:30]), self.str_2_int(k[30:32])]]

    @staticmethod
    def shift_lsb_4_keyword_byte(w):
        """
        :param w: LSB 4 bytes of round key
        :return: rotate 4 bytes
        shift the most right 4 bytes of round key
        K13,K14,K15,K16 -> K14,K15,K16,K13
        """
        x = [w[1], w[2], w[3], w[0]]
        return x

    def sub_lsb_4_keyword_byte(self, x):
        """
        :param x: the LSB 4 bytes of round key
        :return: substitution of SBox
        """
        y = []
        for i in range(4):
            y.append(self.substitute_transform(x[i]))
        return y

    @staticmethod
    def add_rcon_lsb_4_keyword_byte(r, y):
        """
        :param r: a row of Rcon table
        :param y: LSB 4 bytes of round key
        :return: r XOR y
        """
        z = []
        for i in range(4):
            z.append(r[i] ^ y[i])
        return z

    @staticmethod
    def update_round_key(w, z):
        """
        :param w: the current round key
        :param z: the LSB 4 bytes round key auxiliary function output
        :return: the next round key
            w'0 = w0 xor z0
            w'1 = w'0 xor z1
            w'2 = w'1 xor z2
            w'3 = w'2 xor z3
        """
        tmp_w = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_w[i].append((z[j] ^ w[i][j]))
            z = tmp_w[i]
        return tmp_w

    def generate_round_key(self, k, rd):
        """
        :param k: original key matrix
        :param rd: the total number of round
        :return: An array of round key
            pattern:
                1. shift LSB 4 bytes of key
                2. substitute the output of step 1
                3. add round of Rcon to the output of step 2
                4. generate the next round of key
                5. rotate the round key for adding to state
        """
        round_key = [self.rotate_matrix(k)]
        for i in range(rd):
            # Rotate keyword LSB 4 bytes
            x = self.shift_lsb_4_keyword_byte(k[3])
            # Sub keyword LSB 4 bytes
            y = self.sub_lsb_4_keyword_byte(x)
            # Rcon Keyword LSB 4 bytes
            z = self.add_rcon_lsb_4_keyword_byte(self.Rcon[i], y)
            # Keyword round XOR
            k = self.update_round_key(k, z)
            # Rotate Keyword
            round_key.append(self.rotate_matrix(k))
        return round_key

    # Block encryption engine
    @staticmethod
    def str_2_int(s):
        """
        :param s: Hex string
        :return: Integer
        """
        return int.from_bytes(bytes.fromhex(s), byteorder='big')

    @staticmethod
    def int_2_hex(i):
        """
        :param i: int
        :return: hex string
            e.g. 15 -> 0f, 17 -> 11
        """
        return hex(i)[2:].zfill(2).encode()

    def regulate_iv(self, iv):
        """
        :param iv: initial vector
        :return: The IV matrix with type of integer
        split the raw key into 4 x 4 bytes of matrix
        """
        # set a boundary for the raw Plaintext
        if len(iv) > 32:
            raise f"There are {len(iv) - 32} extra bytes in the IV"
        elif len(iv) < 32:
            raise f"There are {len(iv) - 32} missing bytes in the IV"
        return [[self.str_2_int(iv[0:2]), self.str_2_int(iv[2:4]),
                 self.str_2_int(iv[4:6]), self.str_2_int(iv[6:8])],
                [self.str_2_int(iv[8:10]), self.str_2_int(iv[10:12]),
                 self.str_2_int(iv[12:14]), self.str_2_int(iv[14:16])],
                [self.str_2_int(iv[16:18]), self.str_2_int(iv[18:20]),
                 self.str_2_int(iv[20:22]), self.str_2_int(iv[22:24])],
                [self.str_2_int(iv[24:26]), self.str_2_int(iv[26:28]),
                 self.str_2_int(iv[28:30]), self.str_2_int(iv[30:32])]]

    @staticmethod
    def ciphertext_decode(s):
        """
        :param s: ciphertext matrix (type: integer)
        :return: ciphertext with type of hex string
        """
        c = ""
        for row in s:
            for elemt in row:
                c += hex(elemt)[2:].zfill(2)
        return c

    @staticmethod
    def rotate_matrix(m):
        """
        :param m: 4 x 4 matrix
        :return: rotated 4 x 4 matrix
        rotate the rows to the columns
        """
        tmp_m = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_m[j].append(m[i][j])
        return tmp_m

    @staticmethod
    def inv_rotate_matrix(m):
        """
        :param m: 4 x 4 matrix
        :return: rotated 4 x 4 matrix
        rotate the columns to the rows
        """
        tmp_m = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_m[i].append(m[j][i])
        return tmp_m

    def substitute_transform(self, b):
        """
        :param b: bytes (type: int)
        :return: the number in the SBox regards to the given row and column index
            split input byte into 2 x 4bits
            the left 4 bits correspond to row index
            the right 4 bits correspond to column index
        """
        return self.Sbox[b >> 4][b & 0xf]

    @staticmethod
    def add_round_key(s, w):
        """
        :param s: the current round of state matrix
        :param w: the current round of key matrix
        :return: the next state of round = s ^ w
        """
        tmp_s = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_s[i].append((s[i][j] ^ w[i][j]))
        return tmp_s

    def sub_state_bytes(self, s):
        """
        :param s: the current round of state
        :return: substituted state
        """
        tmp_s = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_s[i].append(self.substitute_transform(s[i][j]))
        return tmp_s

    @staticmethod
    def shift_state_row(s):
        """
        :param s: the current round of state
        :return: shifted of state
            e.g.
            s00, s01, s02, s03 ->  s00, s01, s02, s03
            s10, s11, s12. s13 ->  s11, s12, s13, s10
            s20, s21, s22, s23 ->  s22, s23, s20, s21
            s30, s31, s32. s33 ->  s33, s30, s31, s32
        """
        tmp_s = [s[0],
                 [s[1][1], s[1][2], s[1][3], s[1][0]],
                 [s[2][2], s[2][3], s[2][0], s[2][1]],
                 [s[3][3], s[3][0], s[3][1], s[3][2]]]
        return tmp_s

    def mix_column(self, s):
        """
        :param s: the current round of state matrix
        :return: mixed column state
            pattern:
            calculate the product of matrix multiplication and matrix state
            Apply the Galois Field rule to each product result
        """
        multiplication = [[2, 3, 1, 1],
                          [1, 2, 3, 1],
                          [1, 1, 2, 3],
                          [3, 1, 1, 2]]
        tmp_s = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_c = 0
                for k in range(4):
                    tmp_c = tmp_c ^ self.galois_field_256(multiplication[i][k], s[k][j])
                tmp_s[i].append(tmp_c)
        return tmp_s

    def galois_field_256(self, x, i):
        """
        :param x: the element of mix-column multiplication matrix
        :param i: the element of state matrix (1 byte)
        :return: the transformation of x and i
            Galois Field:
                c = a * b (a => [3, 1], b => [255, 0])
            case 1: a = 1
                c = b
            case 2: a = 2
                when b < 128;
                    c = a * b
                when b >= 128 (hex 10);
                    c >= 256 which out of range of 8 bits binary;
                    in this situation,
                    c need to be transformed to 8 bits binary number by using the equation of c ^ 100011011
            case 2: a = 3
                apply b to the pattern of case 2.
                then c = (the output of case 2) ^ b
        """
        m = 0b100011011
        if x == 1:
            return i
        elif x == 2:
            tmp = x * i
            return tmp if i < 128 else tmp ^ int(m)
        elif x == 3:
            return self.galois_field_256(2, i) ^ i

    def encrypt(self, iv, k):
        """
        :param iv: Initial vector matrix
        :param k: array of round key
        :return: the ciphertext
            pattern:
                for round 1 ~ 9
                1. add the round key
                2. substitute the round of state
                3. shift the state rows
                4. mix column of the state
                for round 10
                run step 1, 2, 3 only
        """
        # start_time = time.perf_counter()
        # extract keyword and plaintext
        k = self.regulate_keyword(k)
        s = self.regulate_iv(iv)
        # rotate the keyword and plaintext matrices
        s_rotate = self.rotate_matrix(s)
        round_key = self.generate_round_key(k, self.ROUND)

        for r in range(self.ROUND):
            # print(f"ROUND {r}")
            # Round plaintext XOR keyword
            s_rotate = self.add_round_key(s_rotate, round_key[r])
            # Substitute State
            s_rotate = self.sub_state_bytes(s_rotate)
            # Shift State Rows
            s_rotate = self.shift_state_row(s_rotate)
            if r < 9:
                # Mix State Columns
                s_rotate = self.mix_column(s_rotate)
        # Last State of Round plaintext XOR keyword
        s_rotate = self.add_round_key(s_rotate, round_key[-1])
        s_final = self.inv_rotate_matrix(s_rotate)
        cipher_text = self.ciphertext_decode(s_final)
        # end_time = time.perf_counter()
        # print(f"Process time: {end_time - start_time}")
        return cipher_text

    # Stream encryption mode
    def ctr_mode(self, txt, k, nonce):
        """
        :param txt: raw plaintext
        :param k: key
        :param nonce: initial vector
        :return: ciphertext (in string type hexadecimal)
            patter:
                the CTR (counter) mode requires an initial vector to make a block of cipher into the plaintext.
                the initial vector updates after each block encryption by adding a counter step.
        """
        pad_txt = self.padding_plaintext(txt)
        output = ''
        for i in range(len(pad_txt)):
            output += hex(pad_txt[i] ^
                          self.str_2_int(self.encrypt(hex(self.str_2_int(nonce)
                                                          + i)[2:].zfill(self.hex_num), k)))[2:].zfill(self.hex_num)
        return output

    def ofb_mode(self, txt, k, iv):
        """
        :param txt: raw plaintext
        :param k: key
        :param iv: initial vector
        :return: ciphertext (in string type hexadecimal)
            patter:
                the OFB (output feedback) mode requires an initial vector to make a block of cipher into the plaintext.
                the initial vector will be updated for each block encryption,
                where the block encryption output as the new vector feeds into the next block encryption.
        """
        output = ''
        pad_txt = self.padding_plaintext(txt)
        for i in range(len(pad_txt)):
            iv = self.encrypt(iv, k)
            output += hex(pad_txt[i] ^ self.str_2_int(iv))[2:].zfill(self.hex_num)
        return output

    def cfb_mode(self, txt, k, iv):
        """
        :param txt: raw plaintext
        :param k: key
        :param iv: initial vector
        :return: ciphertext (in string type hexadecimal)
            patter:
                the CFB (cipher feedback) mode requires an initial vector to make a block of cipher into the plaintext.
                the initial vector will be updated for each block encryption,
                where the block cipher as the new vector feeds into the next block encryption.
        """
        output = ''
        pad_txt = self.padding_plaintext(txt)
        for i in range(len(pad_txt)):
            iv = hex(pad_txt[i] ^ self.str_2_int(self.encrypt(iv, k)))[2:].zfill(32)
            output += iv
        return output


if __name__ == '__main__':
    '''
    Plaintext                        | Key                              | Ciphertext
    ---------------------------------|----------------------------------|----------------------------------
    0123456789abcdeffedcba9876543210 | 0f1571c947d9e8590cb7add6af7f6798 | ff0b844a0853bf7c6934ab4364148fb9
    6bc1bee22e409f96e93d7e117393172a | 2b7e151628aed2a6abf7158809cf4f3c | 3ad77bb40d7a3660a89ecaf32466ef97
    00112233445566778899aabbccddeeff | 000102030405060708090a0b0c0d0e0f | 69c4e0d86a7b0430d8cdb78070b4c55a
    000102030405060708090a0b0c0d0e0f | 000102030405060708090a0b0c0d0e0f | 0a940bb5416ef045f1c39458c653ea5a
    00000000000000000000000000000000 | 00000000000000000000000000000000 | 66e94bd4ef8a2c3b884cfa59ca342b2e
    00000000000000000000000000000000 | ffffffffffffffffffffffffffffffff | a1f6258c877d5fcd8964484538bfc92c
    '''
    t = 'helloworld,helloworld,helloworld'
    plaintext = '0123456789abcdeffedcba9876543210'
    key = '0f1571c947d9e8590cb7add6af7f6798'
    # plaintext = '6bc1bee22e409f96e93d7e117393172a'
    # key = '2b7e151628aed2a6abf7158809cf4f3c'
    # plaintext = '00000000000000000000000000000000'
    # key = 'ffffffffffffffffffffffffffffffff'

    aes = AES_128()
    ciphertext = aes.ctr_mode(t, key, plaintext)
    print(f"CTR Mode")
    print(f"plaintext: {t}")
    print(f"Nonce:  {plaintext}")
    print(f"Keyword:    {key}")
    print(f"Ciphertext: {ciphertext}")
    ciphertext = aes.ofb_mode(t, key, plaintext)
    print(f"OFB Mode")
    print(f"plaintext: {t}")
    print(f"Nonce:  {plaintext}")
    print(f"Keyword:    {key}")
    print(f"Ciphertext: {ciphertext}")
    ciphertext = aes.cfb_mode(t, key, plaintext)
    print(f"CFB Mode")
    print(f"plaintext: {t}")
    print(f"Nonce:  {plaintext}")
    print(f"Keyword:    {key}")
    print(f"Ciphertext: {ciphertext}")
