import time

# parameters
Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
Pbox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]


# create a round-key array for each round
def generate_round_key(k, rd):
    round_key = []
    for i in range(1, rd + 1):
        # At round i the 64-bit round key consists of the 64 leftmost bits of the current contents of key.
        round_key.append(k >> 16)
        # print('0x' + hex(round key[i-1])[2:].zfill(16))
        # Rotated 61 bits to the left
        k = ((k & (2 ** 19 - 1)) << 61) + (k >> 19)
        # Pass the left-most four bits through the present S-box
        k = ((Sbox[k >> 76] << 76) + (k & (2 ** 76 - 1)))
        # round number i XOR with bits 19,18,17,16,15 of key
        k ^= i << 15
    return round_key


def add_round_key(s, k):
    return s ^ k


def s_box_layer(text, sbox):
    tmp_text = 0
    for i in range(16):
        tmp_text += sbox[(text >> (i * 4) & 0xf)] << (i * 4)
    return tmp_text


def p_layer(text, pbox):
    tmp_text = 0
    for i in range(64):
        tmp_text += ((text >> i) & 0x01) << pbox[i]
    return tmp_text


def present_encryption(text, k):
    round_key = generate_round_key(k, 32)
    state_text = text
    for i in range(31):
        state_text = add_round_key(state_text, round_key[i])
        state_text = s_box_layer(state_text, Sbox)
        state_text = p_layer(state_text, Pbox)
        # print(f"Round {i+1} output: {'0x'+ hex(state_text)[2:].zfill(16)}")
    state_text = add_round_key(state_text, round_key[-1])
    return state_text


if __name__ == '__main__':
    '''
    Plaintext         | Key                    | Ciphertext
    ------------------|------------------------|-----------------
    00000000 00000000 | 00000000 00000000 0000 | 5579C138 7B228445
    00000000 00000000 | FFFFFFFF FFFFFFFF FFFF | E72C46C0 F5945049
    FFFFFFFF FFFFFFFF | 00000000 00000000 0000 | A112FFC7 2F68417B
    FFFFFFFF FFFFFFFF | FFFFFFFF FFFFFFFF FFFF | 3333DCD3 213210D2
    '''
    plaintext = "0000000000000000"
    plaintext = bytes.fromhex(plaintext)
    plaintext = int.from_bytes(plaintext, byteorder='big')
    key = "FFFFFFFFFFFFFFFFFFFF"
    key = bytes.fromhex(key)
    key = int.from_bytes(key, byteorder='big')
    start_time = time.perf_counter()
    ciphertext = present_encryption(plaintext, key)
    end_time = time.perf_counter()
    print(f"Plaintext: {'0x' + hex(plaintext)[2:].zfill(16)}")
    print(f"Key: {'0x' + hex(key)[2:].zfill(20)}")
    print(f"Ciphertext: {'0x'+ hex(ciphertext)[2:].zfill(16)}")
    print(f"Time used: {end_time-start_time}")
