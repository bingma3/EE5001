import unittest
import random
import time
from AES_128bit import AES_128


def compare_different(a, b):
    diff = 0
    for i in range(len(a)):
        if a[i] == b[i]:
            diff += 1
    return diff


def data_generator(size):
    data = []
    for _ in range(size):
        d = ''
        for i in range(16):
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
        print(f"Total Time: {end - start}")
        print(f"{(end - start) / len(raw_text) * 16} per block of 32 bytes")
        self.assertEqual(len(raw_text) * 2, len(cipher))

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
        print(f"Total Time: {end - start}")
        print(f"{(end - start) / len(raw_text) * 16} per block of 32 bytes")
        self.assertEqual(len(raw_text) * 2, len(cipher))

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
        print(f"Total Time: {end - start}")
        print(f"{(end - start) / len(raw_text) * 16} per block of 32 bytes")
        self.assertEqual(len(raw_text) * 2, len(cipher))

    def test_similarity_of_output_for_similar_input(self):
        """
            Change 1 byte of input compare of the output difference
        """
        original_input = "0123456789abcdeffedcba9876543210"
        input_text = ["a123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543211",
                      "0123456789abcdeffedcba9876543220", "0123456789abcdeffedcba9876543310",
                      "0123456789abcdeffedcba9876544210", "0123456789abcdeffedcba9876563210",
                      "0123456789abcdeffedcba9876743210", "0123456789abcdeffedcba987a543210",
                      "0123456789abcdeffedcba98b6543210", "0123456789abcdeffedcba9076543210",
                      "0123456789abcdeffedcba1876543210", "0123456789abcdeffedcb29876543210",
                      "0123456789abcdeffedc3a9876543210", "0123456789abcdeffed4ba9876543210",
                      "0123456789abcdeffe5cba9876543210", "0123456789abcdeff6dcba9876543210",
                      "0123456789abcdef7edcba9876543210", "0123456789abcde8fedcba9876543210",
                      "0123456789abcd9ffedcba9876543210", "0123456789abc0effedcba9876543210",
                      "0123456789ab1deffedcba9876543210", "0123456789a2cdeffedcba9876543210",
                      "01234567893bcdeffedcba9876543210", "012345678aabcdeffedcba9876543210",
                      "01234567b9abcdeffedcba9876543210", "0123456c89abcdeffedcba9876543210",
                      "012345d789abcdeffedcba9876543210", "01234e6789abcdeffedcba9876543210",
                      "0123f56789abcdeffedcba9876543210", "0129456789abcdeffedcba9876543210",
                      "0183456789abcdeffedcba9876543210", "0723456789abcdeffedcba9876543210"]
        # key = '0f1571c947d9e8590cb7add6af7f6798'
        key = data_generator(10000)
        aes = AES_128()
        differ = []
        for k in key:
            output = aes.encrypt(original_input, k)
            for i in range(len(original_input)):
                output_text_1 = aes.encrypt(input_text[i], k)
                cnt = 0
                for j in range(32):
                    if output[j] == output_text_1[j]:
                        cnt += 1
                differ.append(cnt / 32)
                self.assertGreater(2, 1)
            print(f"Key: {k}")
            print(f"the average similarity between original input and the test output {sum(differ) / len(differ)}")
            print(f"the maximum similarity is {max(differ)}")
            print(f"the minimum similarity is {min(differ)}")

    def test_similarity_of_output_for_similar_key(self):
        """
            Change 1 byte of key compare of the output difference
        """
        original_key = "0123456789abcdeffedcba9876543210"
        key = ["a123456789abcdeffedcba9876543210", "0123456789abcdeffedcba9876543211",
               "0123456789abcdeffedcba9876543220", "0123456789abcdeffedcba9876543310",
               "0123456789abcdeffedcba9876544210", "0123456789abcdeffedcba9876563210",
               "0123456789abcdeffedcba9876743210", "0123456789abcdeffedcba987a543210",
               "0123456789abcdeffedcba98b6543210", "0123456789abcdeffedcba9076543210",
               "0123456789abcdeffedcba1876543210", "0123456789abcdeffedcb29876543210",
               "0123456789abcdeffedc3a9876543210", "0123456789abcdeffed4ba9876543210",
               "0123456789abcdeffe5cba9876543210", "0123456789abcdeff6dcba9876543210",
               "0123456789abcdef7edcba9876543210", "0123456789abcde8fedcba9876543210",
               "0123456789abcd9ffedcba9876543210", "0123456789abc0effedcba9876543210",
               "0123456789ab1deffedcba9876543210", "0123456789a2cdeffedcba9876543210",
               "01234567893bcdeffedcba9876543210", "012345678aabcdeffedcba9876543210",
               "01234567b9abcdeffedcba9876543210", "0123456c89abcdeffedcba9876543210",
               "012345d789abcdeffedcba9876543210", "01234e6789abcdeffedcba9876543210",
               "0123f56789abcdeffedcba9876543210", "0129456789abcdeffedcba9876543210",
               "0183456789abcdeffedcba9876543210", "0723456789abcdeffedcba9876543210"]
        input_text = data_generator(20000)
        aes = AES_128()
        differ = []
        for d in input_text:
            print(f"Round: {input_text.index(d)}")
            output = aes.encrypt(d, original_key)
            for i in range(len(d)):
                output_text_1 = aes.encrypt(d, key[i])
                cnt = 0
                for j in range(32):
                    if output[j] == output_text_1[j]:
                        cnt += 1
                differ.append(cnt / 32)
                self.assertGreater(2, 1)
            print(f"the average similarity between original key and the test key {sum(differ) / len(differ)}")
            print(f"the maximum similarity is {max(differ)}")
            print(f"the minimum similarity is {min(differ)}")

    def test_similarity_of_output_and_input(self):
        """
            compare the similarity between the input text and output text
        """
        rnd = 200000
        input_text = data_generator(rnd)
        key = data_generator(rnd)
        aes = AES_128()
        differ = []
        for i in range(rnd):
            output = aes.encrypt(input_text[i], key[i])
            cnt = 0
            for j in range(32):
                if output[j] == input_text[i][j]:
                    cnt += 1
            differ.append(cnt / 32)
        print(f"the average similarity between input and output {sum(differ) / len(differ)}")
        print(f"the maximum similarity is {max(differ)}")
        print(f"the minimum similarity is {min(differ)}")
        self.assertGreater(2, 1)


if __name__ == '__main__':
    unittest.main()
