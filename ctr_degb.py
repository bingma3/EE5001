from AES_128bit import AES_128
from present_80 import PRESENT_80
import pandas as pd
import time
from PRNG_Randomness_Tests import frequency_test, runs_test, mus_test
from openpyxl import load_workbook


class CTR_DEBG:
    """
    choose engine
        aes128
        present80
    """
    def __init__(self, engine):
        self.name = "ctr_prng"
        self.engine_name = engine
        self.engine = self.get_engine(engine)

    @staticmethod
    def get_engine(engine):
        if engine == 'aes128':
            return AES_128()
        elif engine == 'present80':
            return PRESENT_80()

    def get_seed(self, howmany=1, max=65535, min=0):
        """
        Import randonwrapy.py to generate true random number as seed.
        randonwrapy.py is provided by RANDOM.ORG, that offers ture random numbers to anyone via the Internet.

            The range of true random number is [0x0000, 0xffff]
            for a 128-bit seed number needs generating x8 times
            for 80-bit seed number needs generating x5 times

        :param howmany: total number of random numbers, the default value is 1
        :param max: the maximum boundary of the random numbers, the default value is 65535
        :param min: the minimum boundary of the random numbers, the default value is 0
        :return: array of random numbers, type: int
        """
        print('Generate random number', end='')
        from randomwrapy import rnumlistwithreplacement
        rand_int = []
        for i in range(howmany):
            rand_num = 0
            for j in range(int(self.engine.hex_num/4)):
                # shift 16 bits the current number, add the new random number to the LST 16 bit
                r = int(rnumlistwithreplacement(howmany, max, min)[0])
                rand_num = r + (rand_num << 16)
                print('.', end='')
            rand_int.append(rand_num)
            print('')
        return rand_int

    def prng(self, txt, key, v):
        pad_txt = self.engine.padding_plaintext(txt)
        output = ''
        if type(v) == 'str':
            v = self.engine.str_2_int(v)
        for i in range(len(pad_txt)):
            output += hex(pad_txt[i] ^
                          self.engine.str_2_int(self.engine.encrypt(hex(((v + i)
                                                                         & 0xffffffffffffffffffffffffffffffff))[
                                                                    2:].zfill(self.engine.hex_num),
                                                                    key)))[2:].zfill(self.engine.hex_num)
        return output


if __name__ == '__main__':
    raw_text = ''
    with open('plaintext_sample', 'r') as f:
        lines = f.readlines()
        for line in lines:
            raw_text += line
    bit_length = len(raw_text) * 8  # bit_length equal to total char x 8, where 8 bits in a char
    times_of_run = 10
    engine = 'present80'
    ctr = CTR_DEBG(engine)
    key = ctr.engine.key

    iv = ctr.get_seed(times_of_run)
    table = {'True_Random_Seed': [ctr.engine.int_2_hex(x) for x in iv], 'length_of_bits_string': [],
             'P-value(freq)': [], 'random(freq)': [], 'time(freq)': [],
             'P-value(runs)': [], 'random(runs)': [], 'time(runs)': [],
             'L-bit': [], 'Q': [], 'K': [], 'fn': [],
             'P-value(mus)': [], 'random(mus)': [], 'time(mus)': []}

    for i in range(times_of_run):
        print(f'Test Round {i+1}', end='')
        # frequency test
        start = time.perf_counter()
        e = ctr.engine.str_2_int(ctr.prng(raw_text, ctr.engine.key, iv[i]))
        outcome = frequency_test(e, bit_length)
        end = time.perf_counter()
        table['length_of_bits_string'].append(outcome[0])
        table['P-value(freq)'].append(outcome[1])
        table['random(freq)'].append(outcome[2])
        table['time(freq)'].append(end - start)
        # runs test
        if outcome[2] == 'True':
            start = time.perf_counter()
            e = ctr.engine.str_2_int(ctr.prng(raw_text, ctr.engine.key, iv[i]))
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
        e = ctr.engine.str_2_int(ctr.prng(raw_text, ctr.engine.key, iv[i]))
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
        # print(table)

    path = 'output.xlsx'
    book = load_workbook(path)
    writer = pd.ExcelWriter(path, engine='openpyxl')
    writer.book = book
    df = pd.DataFrame(table)
    df.to_excel(writer, sheet_name=f'{ctr.name}-{time.time_ns()}')
    writer.save()
    writer.close()



