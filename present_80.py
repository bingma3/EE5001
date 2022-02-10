import time
import binascii
# parameters

'''
Plaintext         | Key                    | Ciphertext
------------------|------------------------|-----------------
00000000 00000000 | 00000000 00000000 0000 | 5579C138 7B228445
00000000 00000000 | FFFFFFFF FFFFFFFF FFFF | E72C46C0 F5945049
FFFFFFFF FFFFFFFF | 00000000 00000000 0000 | A112FFC7 2F68417B
FFFFFFFF FFFFFFFF | FFFFFFFF FFFFFFFF FFFF | 3333DCD3 213210D2
'''

ROUND = 32
Sbox = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]
Pbox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]


key = "00000000000000000000"
# key = "11112222333344445555"


# create a round-key array for each round
def update_round_key(key, round):
    roundkey = []
    for i in range(1, round+1):
        # At round i the 64-bit roundkey consists of the 64 leftmost bits of the current contents of key.
        roundkey.append(key >> 16)
        # Rotated 61 bits to the left
        key = ((key & (2**19 - 1)) << 61) + (key >> 19)
        # Pass the left-most four bits through the present S-box
        key = ((Sbox[key >> 76] << 76) + (key & (2 ** 76 - 1)))
        # round number i XOR with bits 19,18,17,16,15 of key
        key = key ^ (i << 15)
    return roundkey


def add_round_key(s, key):
    print(s)
    print(key)
    return s ^ key


def s_box_layer(text, Sbox):
    tmp_text = 0
    for i in range(15, 0, -1):
        tmp_text += Sbox[text >> (4 * i)] << (4 * i)
        text = text - (text >> (4 * i) << (4 * i))
    return tmp_text


def p_layer(text, Pbox):
    tmp_text = 0
    for i in range(63, 0, -1):
        tmp_text += (text >> i << Pbox[i])
        text = text - (text >> i << i)
    return tmp_text




text = "fad89cefbc98afce"
key = bytes.fromhex(key)
text = bytes.fromhex(text)
text = int.from_bytes(text, byteorder='big')
# print(key)
key = int.from_bytes(key, byteorder='big')
roundkey = update_round_key(key, 32)

# print(bin(text))
# print(bin(text - (text >> (4*15) << (4*15))))
tmp_text = 0
for i in range(63, 0, -1):
    print(i)
    tmp_text += (text >> i << Pbox[i])
    text = text - (text >> i << i)
    print(bin(text))
    print(bin(tmp_text))

# print(len(roundkey))
# for k in roundkey:
#     text = add_round_key(text, k)
#     print(hex(text))
# print(bin(key))
# key = ((key & (2**19 - 1)) << 61) + (key >> 19)
# print(bin(key))
# key = ((Sbox[key >> 76] << 76) + (key & (2**76 - 1)))
# # key = (Sbox[key >> 76] << 76)
# print(bin(key))
# # print(bin(((key>>15) & (2**6-1)) ^ 0))
# print(bin((31 << 15) ^ key))