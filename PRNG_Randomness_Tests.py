import pandas as pd
import time
from math import erfc, sqrt


def sum_of_bits(e):
    sum_of_ones_bit = e.bit_count()
    sum_of_zeros_bit = (e.bit_length() - e.bit_count()) * (-1)
    return sum_of_ones_bit + sum_of_zeros_bit


def frequency_test(e):
    """
    Frequency test:
        • This is the most basic test and must be included in any test suite .
        • The purpose of this test is to determine whether the number of ones and
          zeros in a sequence is approximately the same as would be expected for a
          truly random sequence.

    test procedure:
        1. Calculate the sum of bits in sequence (covert 1 is 1, 0 is -1) Sn = X1 + X2+...+Xn , where Xi = 2εi – 1.
        2. Compute the test statistic sobs = abs(Sn)/sqrt(n)
        3. Compute P-value = erfc(sobs/sqrt(2)), where erfc is the complementary error function.
        4. Determine if the sequence is non-random, as P-value is < 0.01

    :return: The table of | True_Random_Seed | length_of_bits_string | P-value | non-random |
    """
    n = e.bit_length()
    sum_bits = sum_of_bits(e)
    s_obs = abs(sum_bits) / sqrt(n)
    p = erfc(s_obs / sqrt(2))
    if p < 0.01:
        r = 'False'
    else:
        r = 'True'
    return n, p, r


def total_num_of_runs(e):
    s = 1
    bit_length = e.bit_length()
    while bit_length > 1:
        if e >> (bit_length - 2) == 1 or e >> (bit_length - 2) == 2:
            s += 1
        e = e - (e >> (bit_length - 1) << (bit_length - 1))
        bit_length -= 1
    return s


def runs_test(e):
    """
    Runs test:
        • The focus of this test is the total number of runs in the sequence , where a
          run is an uninterrupted sequence of identical bits bounded before and after
          with a bit of the opposite value.
        • The purpose of the runs test is to determine whether the number of runs of
          ones and zeros of various lengths is as expected for a random sequence.

    test procedure:
        1. Calculate the frequency of 1 bit in sequence For example, if ε= 1001101011, then n=10 and π= 6/10 = 3/5.
        2. Determine if the prerequisite Frequency test is passed: if |π - 1/2| ≥τ, otherwise P-value is 0
        3. If step 2 is pass, compute V (obs) = sum(r(k)), where r(k)=0 if εk=εk+1, and r(k)=1 otherwise.
        4. Compute P-value = erfc(|V (obs) − 2nπ(1−π)| / 2sqrt(2n)π(1−π))
        5. Determine if the sequence is non-random, as P-value is < 0.01
    :return: The table of | True_Random_Seed | length_of_bits_string | P-value | non-random |
    """
    n = e.bit_length()
    tua = 2 / sqrt(n)
    freq = e.bit_count() / n
    if abs(freq - 0.5) >= tua:
        p = 0
    else:
        vobs = total_num_of_runs(e)
        p = erfc(abs(vobs - (2 * n * freq * (1 - freq))) / (2 * sqrt(2 * n) * freq * (1 - freq)))
    if p < 0.01:
        r = 'False'
    else:
        r = 'True'
    return n, p, r


def mus_test(self):
    """
    Maurer’s universal statistical test:
        • The focus of this test is the number of bits between matching patterns (a
          measure that is related to the length of a compressed sequence).
        • The purpose of the test is to detect whether or not the sequence can be
          significantly compressed without loss of information.
        • A significantly compressible sequence is considered to be non random.
    :return:
    """
    pass


if __name__ == '__main__':
    print(total_num_of_runs(619))
