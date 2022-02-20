import unittest
import time
import random
from present_80 import PRESENT_80


def compare_different(a, b):
    diff = 0
    for i in range(len(a)):
        if a[i] == b[i]:
            diff += 1
    return diff


def data_generator(size, n):
    data = []
    for _ in range(size):
        d = ''
        for i in range(int(n/2)):
            num_byte = random.randint(0, 255)
            str_byte = hex(num_byte)[2:].zfill(2)
            d += str_byte
        data.append(d)
    return data


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

    def test_similarity_of_output_for_similar_input(self):
        """
            Change 1 byte of input compare of the output difference
        """
        original_input = "0000000000000000"
        input_text = ["0000000000000001", "0000000000000020",
                      "0000000000000a00", "0000000000004000",
                      "0000000000030000", "0000000000600000",
                      "000000000f000000", "00000000b0000000",
                      "0000000100000000", "0000003000000000",
                      "0000050000000000", "0000800000000000",
                      "000e000000000000", "00c0000000000000",
                      "0d00000000000000", "9000000000000000"]
        key = data_generator(20000, 20)
        pst = PRESENT_80()
        differ = []
        for k in key:
            output = pst.encrypt(original_input, k)
            for i in range(len(input_text)):
                output_text_1 = pst.encrypt(input_text[i], k)
                cnt = 0
                for j in range(16):
                    if output[j] == output_text_1[j]:
                        cnt += 1
                differ.append(cnt / 16)
        print(f"the average similarity between original input and the test output {sum(differ) / len(differ)}")
        print(f"the maximum similarity is {max(differ)}")
        print(f"the minimum similarity is {min(differ)}")
        self.assertGreater(2, 1)

    def test_similarity_of_output_for_similar_key(self):
        """
            Change 1 byte of key compare of the output difference
        """
        original_key = "FFFFFFFFFFFFFFFFFFFF"
        key = ["FFFFFFFFFFFFFFFFFFF1", "FFFFFFFFF0FFFFFFFFFF",
               "FFFFFFFFFFFFFFFFFF2F", "FFFFFFFF9FFFFFFFFFFF",
               "FFFFFFFFFFFFFFFFF3FF", "FFFFFFF8FFFFFFFFFFFF",
               "FFFFFFFFFFFFFFFF4FFF", "FFFFFF7FFFFFFFFFFFFF",
               "FFFFFFFFFFFFFFF5FFFF", "FFFFF6FFFFFFFFFFFFFF",
               "FFFFFFFFFFFFFF6FFFFF", "FFFF5FFFFFFFFFFFFFFF",
               "FFFFFFFFFFFFF7FFFFFF", "FFF4FFFFFFFFFFFFFFFF",
               "FFFFFFFFFFFF8FFFFFFF", "FF3FFFFFFFFFFFFFFFFF",
               "FFFFFFFFFFF9FFFFFFFF", "F2FFFFFFFFFFFFFFFFFF",
               "FFFFFFFFFF0FFFFFFFFF", "1FFFFFFFFFFFFFFFFFFF"]
        input_text = data_generator(20000, 16)
        pst = PRESENT_80()
        differ = []
        for d in input_text:
            output = pst.encrypt(d, original_key)
            for i in range(len(key)):
                output_text_1 = pst.encrypt(d, key[i])
                cnt = 0
                for j in range(16):
                    if output[j] == output_text_1[j]:
                        cnt += 1
                differ.append(cnt / 16)
        print(f"the average similarity between original key and the test key {sum(differ) / len(differ)}")
        print(f"the maximum similarity is {max(differ)}")
        print(f"the minimum similarity is {min(differ)}")
        self.assertGreater(2, 1)

    def test_similarity_of_output_and_input(self):
        """
            compare the similarity between the input text and output text
        """
        rnd = 200000
        input_text = data_generator(rnd, 16)
        key = data_generator(rnd, 20)
        pst = PRESENT_80()
        differ = []
        for i in range(rnd):
            output = pst.encrypt(input_text[i], key[i])
            cnt = 0
            for j in range(16):
                if output[j] == input_text[i][j]:
                    cnt += 1
            differ.append(cnt / 16)
        print(f"the average similarity between input and output {sum(differ) / len(differ)}")
        print(f"the maximum similarity is {max(differ)}")
        print(f"the minimum similarity is {min(differ)}")
        self.assertGreater(0.5, max(differ))


if __name__ == '__main__':
    unittest.main()
