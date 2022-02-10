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
Pbox = [[0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51],
        [4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55],
        [8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59],
        [12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]]


# key = "0000000000000000000"
key = "11112222333344445555"


def update_round_key(key, round):
    roundkey = []
    for i in range(round):
        # At round i the 64-bit roundkey consists of the 64 leftmost bits of the current contents of key.
        roundkey.append(key >> 16)
        print(bin(roundkey[0]))
        # shift (int 524287 = bin 01111111111111111111
        # key = (key & 524287) << 61 + key >> 18
        print(bin(key))



key = bytes.fromhex(key)
# print(key)
key = int.from_bytes(key, byteorder='big')
print(bin(key))
print(bin(((key & (2**19 - 1)) << 61) + (key >> 19)))
# update_round_key(key, 1)