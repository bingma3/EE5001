from euclidAlgorithm import EUCLID_ALGORITHM
from AES_128bit import AES_128
from present_80 import PRESENT_80
from random import randint
import time
from PRNG_Randomness_Tests import frequency_test, runs_test, mus_test
import pandas as pd
from openpyxl import load_workbook


class BBS_PRNG:
    def __init__(self, engine):
        self.name = "bbs_prng"
        self.engine = self.get_engine(engine)
        self.euclid = EUCLID_ALGORITHM()
        self.prime = self.get_prime(100, 1000)
        self.n = []

    @staticmethod
    def get_engine(engine):
        if engine == 'aes128':
            return AES_128()
        elif engine == 'present80':
            return PRESENT_80()

    @staticmethod
    def seed_generator(howmany=1, max=1000000000, min=0):
        """
        Import randonwrapy.py to generate true random number as seed.
        randonwrapy.py is provided by RANDOM.ORG, that offers ture random numbers to anyone via the Internet.

        :param howmany: the total number of random number, the default value is 1
        :param max: the maximum boundary of the random numbers, the default value is 1000000000
        :param min: the minimum boundary of the random numbers, the default value is 0
        :return: array of random numbers, type: int
        """
        from randomwrapy import rnumlistwithreplacement
        if max > 1000000000:
            max = 1000000000
        rand_int = []
        rand_number = rnumlistwithreplacement(howmany, max, min)
        for i in rand_number:
            rand_int.append(int(i))
        return rand_int

    def get_prime(self, low, high):
        """
            Parser a group of large prime numbers from the prime list
            that the prime number satisfy (number mod 4) = 3
        :param low: lower boundary of the fitted prime
        :param high: higher boundary of the fitted prime
        :return: array of fitted primes
        """
        prime = []
        with open('prime.txt', 'r') as f:
            lines = f.readlines()
            if lines:
                for line in lines:
                    temp = int(line.rstrip())
                    if low < temp < high:
                        try:
                            if self.euclid.mod(4, temp) == 3:
                                prime.append(temp)
                        except Exception as e:
                            pass
        return prime

    def get_n(self, howmany):
        """
            Randomly pick up two primes p, q from the array
            note: the two primes are not equal
        :return: n=p*q
        """
        n = []
        for _ in range(howmany):
            tmp_prime = list(self.prime)
            p = tmp_prime[randint(0, len(tmp_prime)-1)]
            tmp_prime.remove(p)
            q = tmp_prime[randint(0, len(tmp_prime)-1)]
            n.append(p*q)
        return n

    def get_seed(self, howmany, n):
        """
            Pick up a random number as Seed s
            that GCD of s, n equal to 1
            seed is not 0 or 1
        :return: the seed s
        """
        print('Generate random number ', end='')
        rand_seed = []
        i = 0
        while 1:
            s = self.seed_generator(1, n[i], 2)[0]
            if self.euclid.find_gcd(s, n[i]) == 1:
                rand_seed.append(s)
                i += 1
                print('.', end='')
                if i == howmany:
                    print('')
                    return rand_seed

    def bbs_generator(self, seed, n, bit_length):
        """

        :param seed: random number
        :param n: product of two large primes
        :param bit_length: bit length of seed
        :return: bit sequence
        """
        x = self.euclid.mod(n, seed ** 2)
        b = 0
        for i in range(bit_length):
            x = self.euclid.mod(n, x ** 2)
            b += x % 2 << i
        return b

    def prng(self, txt, key, seeds, n):
        pad_txt = self.engine.padding_plaintext(txt)
        output = ''
        for i in range(len(pad_txt)):
            v = self.bbs_generator(seeds[i], n[i], self.engine.hex_num * 4)
            output += hex(
                pad_txt[i] ^ self.engine.str_2_int(self.engine.encrypt(hex(v)[2:].zfill(self.engine.hex_num), key)))[
                      2:].zfill(self.engine.hex_num)
        return output


if __name__ == '__main__':
    raw_text = ''
    with open('plaintext_sample', 'r') as f:
        lines = f.readlines()
        for line in lines:
            raw_text += line
    bit_length = len(raw_text)*8     # bit_length equal to total char x 8, where 8 bits in a char
    times_of_run = 10
    engine = 'present80'
    bbs = BBS_PRNG(engine)
    key = bbs.engine.key

    table = {'length_of_bits_string': [],
             'P-value(freq)': [], 'random(freq)': [], 'time(freq)': [],
             'P-value(runs)': [], 'random(runs)': [], 'time(runs)': [],
             'L-bit': [], 'Q': [], 'K': [], 'fn': [],
             'P-value(mus)': [], 'random(mus)': [], 'time(mus)': []}

    for i in range(times_of_run):
        print(f'Test Round {i+1}')
        block_num = len(bbs.engine.padding_plaintext(raw_text))
        n = bbs.get_n(block_num)
        seeds = bbs.get_seed(block_num, n)
        #  frequency test
        start = time.perf_counter()
        e = bbs.engine.str_2_int(bbs.prng(raw_text, bbs.engine.key, seeds, n))
        outcome = frequency_test(e, bit_length)
        end = time.perf_counter()
        table['length_of_bits_string'].append(outcome[0])
        table['P-value(freq)'].append(outcome[1])
        table['random(freq)'].append(outcome[2])
        table['time(freq)'].append(end-start)
        # runs test
        if outcome[2] == 'True':
            start = time.perf_counter()
            e = bbs.engine.str_2_int(bbs.prng(raw_text, bbs.engine.key, seeds, n))
            outcome = runs_test(e, bit_length)
            end = time.perf_counter()
            table['P-value(runs)'].append(outcome[1])
            table['random(runs)'].append(outcome[2])
            table['time(runs)'].append(end - start)
        else:
            table['P-value(runs)'].append('n/a')
            table['random(runs)'].append('n/a')
            table['time(runs)'].append('n/a')
        # Maurer’s universal statistical test
        start = time.perf_counter()
        e = bbs.engine.str_2_int(bbs.prng(raw_text, bbs.engine.key, seeds, n))
        outcome = mus_test(e, bit_length)
        end = time.perf_counter()
        table['L-bit'].append(outcome[0])
        table['Q'].append(outcome[1])
        table['K'].append(outcome[2])
        table['fn'].append(outcome[3])
        table['P-value(mus)'].append(outcome[4])
        table['random(mus)'].append(outcome[5])
        table['time(mus)'].append(end - start)
        print(' ... checked')

    path = 'output.xlsx'
    book = load_workbook(path)
    writer = pd.ExcelWriter(path, engine='openpyxl')
    writer.book = book
    df = pd.DataFrame(table)
    df.to_excel(writer, sheet_name=f'{bbs.name}-{time.time_ns()}')
    writer.save()
    writer.close()

