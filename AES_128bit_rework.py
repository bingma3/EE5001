import time


class ASE_128:
    def __init__(self, rnd=10):
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

    @staticmethod
    def str_2_int(s):
        return int.from_bytes(bytes.fromhex(s), byteorder='big')

    def padding_keyword(self, k):
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

    def padding_plaintext(self, txt):
        if len(txt) > 32:
            raise f"There are {len(txt) - 32} extra bytes in the Plaintext"
        elif len(txt) < 32:
            raise f"There are {len(txt) - 32} missing bytes in the Plaintext"
        return [[self.str_2_int(txt[0:2]), self.str_2_int(txt[2:4]),
                 self.str_2_int(txt[4:6]), self.str_2_int(txt[6:8])],
                [self.str_2_int(txt[8:10]), self.str_2_int(txt[10:12]),
                 self.str_2_int(txt[12:14]), self.str_2_int(txt[14:16])],
                [self.str_2_int(txt[16:18]), self.str_2_int(txt[18:20]),
                 self.str_2_int(txt[20:22]), self.str_2_int(txt[22:24])],
                [self.str_2_int(txt[24:26]), self.str_2_int(txt[26:28]),
                 self.str_2_int(txt[28:30]), self.str_2_int(txt[30:32])]]

    @staticmethod
    def insert_ciphertext(s):
        c = ""
        for row in s:
            for elemt in row:
                c += hex(elemt)[2:].zfill(2)
        # print(f"The Ciphertext is {c}")
        return c

    @staticmethod
    def rotate_matrix(m):
        tmp_m = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_m[j].append(m[i][j])
        # print(f"Rotate Matrix")
        # for r in m:
        #     print(r)
        # print(f"to Matrix")
        # for r in tmp_m:
        #     print(r)
        return tmp_m

    @staticmethod
    def inv_rotate_matrix(m):
        tmp_m = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_m[i].append(m[j][i])
        # print(f"Inverse Rotate Matrix")
        # for r in m:
        #     print(r)
        # print(f"to Matrix")
        # for r in tmp_m:
        #     print(r)
        return tmp_m

    @staticmethod
    def shift_lsb_4_keyword_byte(w):
        x = [w[1], w[2], w[3], w[0]]
        # print(f"shift LSB 4 bytes Keyword {w} to {x}")
        return x

    def substitute_transform(self, b):
        return self.Sbox[b >> 4][b & 0xf]

    def sub_lsb_4_keyword_byte(self, x):
        y = []
        for i in range(4):
            y.append(self.substitute_transform(x[i]))
        # print(f"Substitute Key Word {x} to {y}")
        return y

    @staticmethod
    def int_2_hex(i):
        return hex(i)[2:].zfill(2).encode()

    @staticmethod
    def add_rcon_lsb_4_keyword_byte(r, y):
        z = []
        for i in range(4):
            z.append(r[i] ^ y[i])
        # print(f"Key Word {y} XOR Rcon {r} is {z}")
        return z

    @staticmethod
    def update_round_key(w, z):
        tmp_w = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_w[i].append((z[j] ^ w[i][j]))
            z = tmp_w[i]
            # print(f"Key Word {i} is {tmp_w[i]}")
        return tmp_w

    @staticmethod
    def add_round_key(s, w):
        tmp_s = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_s[i].append((s[i][j] ^ w[i][j]))
        # print(f"New state is:")
        # for r in tmp_s:
        #     print(r)
        return tmp_s

    def sub_state_bytes(self, s):
        tmp_s = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_s[i].append(self.substitute_transform(s[i][j]))
        # print(f"Substitute State")
        # for r in s:
        #     print(r)
        # print('to Sub-State')
        # for r in tmp_s:
        #     print(r)
        return tmp_s

    @staticmethod
    def shift_state_row(s):
        tmp_s = [s[0],
                 [s[1][1], s[1][2], s[1][3], s[1][0]],
                 [s[2][2], s[2][3], s[2][0], s[2][1]],
                 [s[3][3], s[3][0], s[3][1], s[3][2]]]
        # print(f"Shift State")
        # for r in s:
        #     print(r)
        # print('to')
        # for r in tmp_s:
        #     print(r)
        return tmp_s

    def mix_column(self, s):
        mask = [[2, 3, 1, 1],
                [1, 2, 3, 1],
                [1, 1, 2, 3],
                [3, 1, 1, 2]]
        tmp_s = [[], [], [], []]
        for i in range(4):
            for j in range(4):
                tmp_c = 0
                for k in range(4):
                    tmp_c = tmp_c ^ self.galois_field_256(mask[i][k], s[k][j])
                tmp_s[i].append(tmp_c)
        # print(f"Mix Column State")
        # for r in s:
        #     print(r)
        # print('to')
        # for r in tmp_s:
        #     print(r)
        return tmp_s

    def galois_field_256(self, const, i):
        m = 0b100011011
        if const == 1:
            return i
        elif const == 2:
            tmp = const * i
            return tmp if i < 128 else tmp ^ int(m)
        elif const == 3:
            return self.galois_field_256(2, i) ^ i

    def generate_round_key(self, k, rd):
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

    def encrypt(self, txt, k):
        start_time = time.perf_counter()
        # extract keyword and plaintext
        k = self.padding_keyword(k)
        s = self.padding_plaintext(txt)
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
        cipher_text = self.insert_ciphertext(s_final)
        end_time = time.perf_counter()
        print(f"Process time: {end_time - start_time}")
        return cipher_text


if __name__ == '__main__':
    plaintext = '0123456789abcdeffedcba9876543210'
    key = '0f1571c947d9e8590cb7add6af7f6798'
    # plaintext = '6bc1bee22e409f96e93d7e117393172a'
    # key = '2b7e151628aed2a6abf7158809cf4f3c'
    aes = ASE_128()
    ciphertext = aes.encrypt(plaintext, key)
    print(f"Plaintext:  {plaintext}")
    print(f"Keyword:    {key}")
    print(f"Ciphertext: {ciphertext}")
