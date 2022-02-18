import unittest
import time
from present_80 import PRESENT_80


class MyTestCase(unittest.TestCase):
    def test_ctr_mode(self):
        raw_text = ''
        with open('plaintext_sample', 'r') as f:
            lines = f.readlines()
            for line in lines:
                raw_text += line
        start = time.perf_counter()
        key = 'FFFFFFFFFFFFFFFFFFFF'
        iv = '0000000000000000'
        present = PRESENT_80()
        cipher = present.ctr_mode(raw_text, key, iv)
        end = time.perf_counter()
        print("\n******Test CTR Mode******")
        print(f"Plain text length: {len(raw_text)} characters")
        print(f"key: {key}")
        print(f"initial vector: {iv}")
        print(f"Cipher text length: {len(cipher)} characters")
        print(f"Total Time: {end-start}")
        print(f"{(end-start)/len(raw_text)*16} per block of 32 bytes")
        self.assertEqual(len(raw_text)*2, len(cipher))

    def test_ofb_mode(self):
        raw_text = ''
        with open('plaintext_sample', 'r') as f:
            lines = f.readlines()
            for line in lines:
                raw_text += line
        start = time.perf_counter()
        key = 'FFFFFFFFFFFFFFFFFFFF'
        iv = '0000000000000000'
        present = PRESENT_80()
        cipher = present.ofb_mode(raw_text, key, iv)
        end = time.perf_counter()
        print("\n******Test OFB Mode******")
        print(f"Plain text length: {len(raw_text)} characters")
        print(f"key: {key}")
        print(f"initial vector: {iv}")
        print(f"Cipher text length: {len(cipher)} characters")
        print(f"Total Time: {end-start}")
        print(f"{(end-start)/len(raw_text)*16} per block of 32 bytes")
        self.assertEqual(len(raw_text)*2, len(cipher))

    def test_cfb_mode(self):
        raw_text = ''
        with open('plaintext_sample', 'r') as f:
            lines = f.readlines()
            for line in lines:
                raw_text += line
        start = time.perf_counter()
        key = 'FFFFFFFFFFFFFFFFFFFF'
        iv = '0000000000000000'
        present = PRESENT_80()
        cipher = present.cfb_mode(raw_text, key, iv)
        end = time.perf_counter()
        print("\n******Test CFB Mode******")
        print(f"Plain text length: {len(raw_text)} characters")
        print(f"key: {key}")
        print(f"initial vector: {iv}")
        print(f"Cipher text length: {len(cipher)} characters")
        print(f"Total Time: {end-start}")
        print(f"{(end-start)/len(raw_text)*16} per block of 32 bytes")
        self.assertEqual(len(raw_text)*2, len(cipher))


if __name__ == '__main__':
    unittest.main()
