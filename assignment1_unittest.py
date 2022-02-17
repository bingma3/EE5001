import unittest
from AES_128bit import ASE_128
from present_80 import PRESENT_80


class MyTestCase(unittest.TestCase):
    def test_aes_encrypt(self):
        test_plaintext = ['0123456789abcdeffedcba9876543210',
                          '6bc1bee22e409f96e93d7e117393172a',
                          '00112233445566778899aabbccddeeff',
                          '000102030405060708090a0b0c0d0e0f',
                          '00000000000000000000000000000000',
                          '00000000000000000000000000000000']
        test_key = ['0f1571c947d9e8590cb7add6af7f6798',
                    '2b7e151628aed2a6abf7158809cf4f3c',
                    '000102030405060708090a0b0c0d0e0f',
                    '000102030405060708090a0b0c0d0e0f',
                    '00000000000000000000000000000000',
                    'ffffffffffffffffffffffffffffffff']
        test_ciphertext = ['ff0b844a0853bf7c6934ab4364148fb9',
                           '3ad77bb40d7a3660a89ecaf32466ef97',
                           '69c4e0d86a7b0430d8cdb78070b4c55a',
                           '0a940bb5416ef045f1c39458c653ea5a',
                           '66e94bd4ef8a2c3b884cfa59ca342b2e',
                           'a1f6258c877d5fcd8964484538bfc92c']
        aes = ASE_128()
        for _ in range(100):
            for i in range(len(test_plaintext)):
                self.assertEqual(aes.encrypt(test_plaintext[i], test_key[i]), test_ciphertext[i])

    def test_present_encrypt(self):
        test_plaintext = ['0000000000000000',
                          '0000000000000000',
                          'FFFFFFFFFFFFFFFF',
                          'FFFFFFFFFFFFFFFF']
        test_key = ['0000000000000000',
                    'FFFFFFFFFFFFFFFFFFFF',
                    '0000000000000000',
                    'FFFFFFFFFFFFFFFFFFFF']
        test_ciphertext = ['5579C1387B228445',
                           'E72C46C0F5945049',
                           'A112FFC72F68417B',
                           '3333DCD3213210D2']
        present = PRESENT_80()
        for _ in range(100):
            for i in range(len(test_plaintext)):
                self.assertEqual(present.encrypt(test_plaintext[i], test_key[i]).upper(), test_ciphertext[i])


if __name__ == '__main__':
    unittest.main()
