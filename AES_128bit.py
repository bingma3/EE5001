import time

# parameters

ROUND = 10
Rcon = [[b'01', b'00', b'00', b'00'],
        [b'02', b'00', b'00', b'00'],
        [b'04', b'00', b'00', b'00'],
        [b'08', b'00', b'00', b'00'],
        [b'10', b'00', b'00', b'00'],
        [b'20', b'00', b'00', b'00'],
        [b'40', b'00', b'00', b'00'],
        [b'80', b'00', b'00', b'00'],
        [b'1B', b'00', b'00', b'00'],
        [b'36', b'00', b'00', b'00']]
Sbox = [
    [b'63', b'7C', b'77', b'7B', b'F2', b'6B', b'6F', b'C5', b'30', b'01', b'67', b'2B', b'FE', b'D7', b'AB', b'76'],
    [b'CA', b'82', b'C9', b'7D', b'FA', b'59', b'47', b'F0', b'AD', b'D4', b'A2', b'AF', b'9C', b'A4', b'72', b'C0'],
    [b'B7', b'FD', b'93', b'26', b'36', b'3F', b'F7', b'CC', b'34', b'A5', b'E5', b'F1', b'71', b'D8', b'31', b'15'],
    [b'04', b'C7', b'23', b'C3', b'18', b'96', b'05', b'9A', b'07', b'12', b'80', b'E2', b'EB', b'27', b'B2', b'75'],
    [b'09', b'83', b'2C', b'1A', b'1B', b'6E', b'5A', b'A0', b'52', b'3B', b'D6', b'B3', b'29', b'E3', b'2F', b'84'],
    [b'53', b'D1', b'00', b'ED', b'20', b'FC', b'B1', b'5B', b'6A', b'CB', b'BE', b'39', b'4A', b'4C', b'58', b'CF'],
    [b'D0', b'EF', b'AA', b'FB', b'43', b'4D', b'33', b'85', b'45', b'F9', b'02', b'7F', b'50', b'3C', b'9F', b'A8'],
    [b'51', b'A3', b'40', b'8F', b'92', b'9D', b'38', b'F5', b'BC', b'B6', b'DA', b'21', b'10', b'FF', b'F3', b'D2'],
    [b'CD', b'0C', b'13', b'EC', b'5F', b'97', b'44', b'17', b'C4', b'A7', b'7E', b'3D', b'64', b'5D', b'19', b'73'],
    [b'60', b'81', b'4F', b'DC', b'22', b'2A', b'90', b'88', b'46', b'EE', b'B8', b'14', b'DE', b'5E', b'0B', b'DB'],
    [b'E0', b'32', b'3A', b'0A', b'49', b'06', b'24', b'5C', b'C2', b'D3', b'AC', b'62', b'91', b'95', b'E4', b'79'],
    [b'E7', b'C8', b'37', b'6D', b'8D', b'D5', b'4E', b'A9', b'6C', b'56', b'F4', b'EA', b'65', b'7A', b'AE', b'08'],
    [b'BA', b'78', b'25', b'2E', b'1C', b'A6', b'B4', b'C6', b'E8', b'DD', b'74', b'1F', b'4B', b'BD', b'8B', b'8A'],
    [b'70', b'3E', b'B5', b'66', b'48', b'03', b'F6', b'0E', b'61', b'35', b'57', b'B9', b'86', b'C1', b'1D', b'9E'],
    [b'E1', b'F8', b'98', b'11', b'69', b'D9', b'8E', b'94', b'9B', b'1E', b'87', b'E9', b'CE', b'55', b'28', b'DF'],
    [b'8C', b'A1', b'89', b'0D', b'BF', b'E6', b'42', b'68', b'41', b'99', b'2D', b'0F', b'B0', b'54', b'BB', b'16']]


def extract_keyword(key):
    if len(key) > 32:
        raise f"There are {len(key) - 32} extra bytes in the Keyword"
    elif len(key) < 32:
        raise f"There are {len(key) - 32} missing bytes in the Keyword"
    return [[key[0:2], key[2:4], key[4:6], key[6:8]],
            [key[8:10], key[10:12], key[12:14], key[14:16]],
            [key[16:18], key[18:20], key[20:22], key[22:24]],
            [key[24:26], key[26:28], key[28:30], key[30:32]]]


def extract_plaintext(text):
    if len(key) > 32:
        raise f"There are {len(key) - 32} extra bytes in the Plaintext"
    elif len(key) < 32:
        raise f"There are {len(key) - 32} missing bytes in the Plaintext"
    return [[text[0:2], text[2:4], text[4:6], text[6:8]],
            [text[8:10], text[10:12], text[12:14], text[14:16]],
            [text[16:18], text[18:20], text[20:22], text[22:24]],
            [text[24:26], text[26:28], text[28:30], text[30:32]]]


def insert_ciphertext(s):
    c = b''
    for row in s:
        for elemt in row:
            c += elemt
    print(f"The Ciphertext is {c}")
    return c


def rotate_matrix(m):
    tmp_m = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            tmp_m[j].append(m[i][j])
    print(f"Rotate Matrix")
    for r in m:
        print(r)
    print(f"to Matrix")
    for r in tmp_m:
        print(r)
    return tmp_m


def inv_rotate_matrix(m):
    tmp_m = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            tmp_m[i].append(m[j][i])
    print(f"Inverse Rotate Matrix")
    for r in m:
        print(r)
    print(f"to Matrix")
    for r in tmp_m:
        print(r)
    return tmp_m


def rotate_keyword(w):
    x = [w[1], w[2], w[3], w[0]]
    print(f"Rotate Key Word {w} to {x}")
    return x


def substitute_transform(b):
    return Sbox[int(b[:1].decode(), 16)][int(b[1:].decode(), 16)].lower()


def sub_keyword(x):
    y = []
    for i in range(4):
        y.append(substitute_transform(x[i]))
    print(f"Substitute Key Word {x} to {y}")
    return y


def int_2_hex(i):
    return hex(i)[2:].zfill(2).encode()


def byte_XOR(a, b):
    if int(a, 16) == 0:
        return b
    elif int(b, 16) == 0:
        return a
    return int_2_hex(int(a, 16) ^ int(b, 16))


def rcon_xor(r, y):
    z = []
    for i in range(4):
        z.append(byte_XOR(r[i], y[i]))
    print(f"Key Word {y} XOR Rcon {r} is {z}")
    return z


def round_xor(w, z):
    tmp_w = [[], [], [], []]
    for i in range(4):
        # print(w[i], z)
        for j in range(4):
            tmp_w[i].append(byte_XOR(z[j], w[i][j]))
        z = tmp_w[i]
        print(f"Key Word {i} is {tmp_w[i]}")
    return tmp_w


def state_xor_roundkey(s, w):
    tmp_s = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            tmp_s[i].append(byte_XOR(s[i][j], w[i][j]))
    print(f"New state is:")
    for r in tmp_s:
        print(r)
    return tmp_s


def sub_state_bytes(s):
    tmp_s = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            tmp_s[i].append(substitute_transform(s[i][j]))
    print(f"Substitute State")
    for r in s:
        print(r)
    print('to Sub-State')
    for r in tmp_s:
        print(r)
    return tmp_s


def shift_state_row(s):
    tmp_s = [s[0],
             [s[1][1], s[1][2], s[1][3], s[1][0]],
             [s[2][2], s[2][3], s[2][0], s[2][1]],
             [s[3][3], s[3][0], s[3][1], s[3][2]]]
    print(f"Shift State")
    for r in s:
        print(r)
    print('to')
    for r in tmp_s:
        print(r)
    return tmp_s


def mix_column(s):
    mask = [[2, 3, 1, 1],
            [1, 2, 3, 1],
            [1, 1, 2, 3],
            [3, 1, 1, 2]]
    tmp_s = [[], [], [], []]
    for i in range(4):
        for j in range(4):
            tmp_c = 0
            for k in range(4):
                tmp_c = tmp_c ^ galois_field_256(mask[i][k], s[k][j])
            tmp_s[i].append(int_2_hex(tmp_c))
    print(f"Mix Column State")
    for r in s:
        print(r)
    print('to')
    for r in tmp_s:
        print(r)
    return tmp_s


def galois_field_256(const, i):
    m = 0b100011011
    if const == 1:
        return int(i, 16)
    elif const == 2:
        tmp = const * int(i, 16)
        return tmp if int(i, 16) < 128 else tmp ^ int(m)
    elif const == 3:
        return galois_field_256(2, i) ^ int(i, 16)


def aes_encrypt(plaintext, key):
    start_time = time.perf_counter()
    # extract keyword and plaintext
    w = extract_keyword(key)
    s = extract_plaintext(plaintext)
    # rotate the keyword and plaintext matrices
    s_rotate = rotate_matrix(s)
    w_rotate = rotate_matrix(w)

    for r in range(ROUND):
        print(f"ROUND {r}")
        if r < 9:
            # Round plaintext XOR keyword
            s_rotate = state_xor_roundkey(s_rotate, w_rotate)
            # Substitute State
            s_rotate = sub_state_bytes(s_rotate)
            # Shift State Rows
            s_rotate = shift_state_row(s_rotate)
            # Mix State Columns
            s_rotate = mix_column(s_rotate)
            # Rotate keyword LSB 4 bytes
            x = rotate_keyword(w[3])
            # Sub keyword LSB 4 bytes
            y = sub_keyword(x)
            # Rcon Keyword LSB 4 bytes
            z = rcon_xor(Rcon[r], y)
            # Keyword round XOR
            w = round_xor(w, z)
            # Rotate Keyword
            w_rotate = rotate_matrix(w)

        else:
            # Round plaintext XOR keyword
            s_rotate = state_xor_roundkey(s_rotate, w_rotate)
            # Substitute State
            s_rotate = sub_state_bytes(s_rotate)
            # Shift State Rows
            s_rotate = shift_state_row(s_rotate)
            # Rotate keyword LSB 4 bytes
            x = rotate_keyword(w[3])
            # Sub keyword LSB 4 bytes
            y = sub_keyword(x)
            # Rcon Keyword LSB 4 bytes
            z = rcon_xor(Rcon[r], y)
            # Keyword round XOR
            w = round_xor(w, z)
            # Rotate Keyword
            w_rotate = rotate_matrix(w)
    # Round plaintext XOR keyword
    s_rotate = state_xor_roundkey(s_rotate, w_rotate)
    s_final = inv_rotate_matrix(s_rotate)
    cipher_text = insert_ciphertext(s_final)
    end_time = time.perf_counter()
    print(f"Process time: {end_time-start_time}")
    return cipher_text


if __name__ == '__main__':
    plaintext = b'0123456789abcdeffedcba9876543210'
    key = b'0e1571c947d9e8590cb7add6af7f6798'
    ciphertext = aes_encrypt(plaintext, key)
    print(f"Plaintext:  {plaintext}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Keyword:    {key}")

