import unittest
import time
from AES_128bit import AES_128


class MyTestCase(unittest.TestCase):
    def test_ctr_mode(self):
        raw_text = ''
        with open('plaintext_sample', 'r') as f:
            lines = f.readlines()
            for line in lines:
                raw_text += line
        start = time.perf_counter()
        key = '0f1571c947d9e8590cb7add6af7f6798'
        iv = '0123456789abcdeffedcba9876543210'
        aes = AES_128()
        cipher = aes.ctr_mode(raw_text, key, iv)
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
        key = '0f1571c947d9e8590cb7add6af7f6798'
        iv = '0123456789abcdeffedcba9876543210'
        aes = AES_128()
        cipher = aes.ofb_mode(raw_text, key, iv)
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
        key = '0f1571c947d9e8590cb7add6af7f6798'
        iv = '0123456789abcdeffedcba9876543210'
        aes = AES_128()
        cipher = aes.cfb_mode(raw_text, key, iv)
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
