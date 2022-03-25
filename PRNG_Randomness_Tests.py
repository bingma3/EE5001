from math import erfc, sqrt, pow, log2


def sum_of_bits(e, n):
    sum_of_ones_bit = e.bit_count()
    sum_of_zeros_bit = (n - sum_of_ones_bit) * (-1)
    return sum_of_ones_bit + sum_of_zeros_bit


def frequency_test(e, n):
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
    sum_bits = sum_of_bits(e, n)
    s_obs = abs(sum_bits) / sqrt(n)
    p = erfc(s_obs / sqrt(2))
    if p < 0.01:
        r = 'False'
    else:
        r = 'True'
    return n, p, r


def total_num_of_runs(e, n):
    s = 1
    bit_length = n
    while bit_length > 1:
        if e >> (bit_length - 2) == 1 or e >> (bit_length - 2) == 2:
            s += 1
        e = e - (e >> (bit_length - 1) << (bit_length - 1))
        bit_length -= 1
    return s


def runs_test(e, n):
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

    :return: [ True_Random_Seed | length_of_bits_string | P-value | non-random ]
    """
    tua = 2 / sqrt(n)
    freq = e.bit_count() / n
    if abs(freq - 0.5) >= tua:
        p = 0
    else:
        vobs = total_num_of_runs(e, n)
        p = erfc(abs(vobs - (2 * n * freq * (1 - freq))) / (2 * sqrt(2 * n) * freq * (1 - freq)))
    if p < 0.01:
        r = 'False'
    else:
        r = 'True'
    return n, p, r


def determine_L_bit(n):
    """
    The first segment consists of Q initialization blocks,
    where Q should be chosen so that Q = 10*pow(2, L).
    The second segment consists of K test blocks, where K= n/L-Q ≈ 1000*pow(2, L). .
    :param n: sequence length
    :return: L-bit
    """
    if n < 24240:
        return 2
    elif n < 64640:
        return 3
    elif n < 161600:
        return 4
    elif n < 387840:
        return 5
    elif n < 904960:
        return 6
    elif n < 2068480:
        return 7
    elif n < 4654080:
        return 8
    elif n < 10342400:
        return 9
    elif n < 22753280:
        return 10
    elif n < 49643520:
        return 11
    elif n < 107560960:
        return 12
    elif n < 231669760:
        return 13
    elif n < 496435200:
        return 14
    elif n < 1059061760:
        return 15
    else:
        return 16


def L_bit_last_occurrence(init_seg, seg_length, l_bit):
    """
    Generate Possible L-bit Value table

    :param init_seg: initialization segment
    :param seg_length: initialization segment bit length
    :param l_bit: L-bit
    :return: L-bit last occurrence array
    """
    last_occurrence = [0] * int(pow(2, l_bit))
    pos = 1
    while seg_length > 0:
        i = init_seg >> (seg_length - l_bit)
        last_occurrence[i] = pos
        init_seg = init_seg - (init_seg >> (seg_length - l_bit) << (seg_length - l_bit))
        seg_length -= l_bit
        pos += 1
    return last_occurrence


def accumulate_log2_sum(test_seg, seg_length, l_bit, init_table, pos):
    """
    log2 sum of all the differences detected in the K blocks (i.e., sum = sum + log2(i – Tj))

    :param test_seg: test segment
    :param seg_length: test segment bit length
    :param l_bit: L-bit
    :param init_table: L-bit last occurrence initial table
    :param pos: the position of the first L-bit of test segment in the full segment
    :return: sum log2
    """
    sum = 0
    while seg_length > 0:
        i = test_seg >> (seg_length - l_bit)
        Tj = init_table[i]      # get L-bit last occurrence
        sum = sum + log2(pos - Tj)
        init_table[i] = pos     # update L-bit last occurrence
        test_seg = test_seg - (test_seg >> (seg_length - l_bit) << (seg_length - l_bit))  # remove L-bit from segment
        seg_length -= l_bit     # update segment length
        pos += 1  # increment index
    return sum


def get_mean_and_variance(l_bit):
    """
    Mean µ and variance σ2 of the statistic table references from the “Handbook of Applied Cryptography.”
    https://cacr.uwaterloo.ca/hac/about/chap5.pdf, 5.4.5 Maurer’s universal statistical test, Table 5.3

    :param l_bit: L-bit
    :return: (expectedValue, variance)
    """
    mean_variance_table = [(0.7326495, 0.690), (1.5374383, 1.338), (2.4016068, 1.901), (3.3112247, 2.358),
                           (4.2534266, 2.705), (5.2177052, 2.954), (6.1962507, 3.125), (7.1836656, 3.238),
                           (8.1764248, 3.311), (9.1723243, 3.356), (10.170032, 3.384), (11.168765, 3.401),
                           (12.168070, 3.410), (13.167693, 3.416), (14.167488, 3.419), (15.167379, 3.421)]

    return mean_variance_table[l_bit-1]


def mus_test(e, n):
    """
    Maurer’s universal statistical test:
        • The focus of this test is the number of bits between matching patterns (a
          measure that is related to the length of a compressed sequence).
        • The purpose of the test is to detect whether or not the sequence can be
          significantly compressed without loss of information.
        • A significantly compressible sequence is considered to be non random.

    test procedure:
        1. Initial segment Q of L-bit non-overlapping blocks, The remaining K blocks are the test blocks (K= n/L - Q),
            where n is the length of sequence e.Where Q should be chosen so that Q = 10*pow(2, L)
        2. Use Q to create a table for each possible L-bit value. he block number of the last occurrence of each L-bit
            block is noted in the table.
        3. Add the calculated distance between re-occurrences of the same L-bit block to an accumulating log2 sum of all
            the differences detected in the K blocks (i.e., sum = sum + log2(i – Tj)).
        4. Compute the test statistic: fn = sum(log2(i – Tj))/K
        5. Compute P-value = erfc((|fn - expectedValue(L)|)/(sqrt(2)σ))
        6. Determine if the sequence is non-random, as P-value is < 0.01

    :param e: n-bit sequence
    :param n: sequence length
    :return: n, P-value, randomness
    """

    # initialisation
    l_bit = determine_L_bit(n)
    Q = int(10*pow(2, l_bit))
    K = int(n/l_bit) - Q

    # discard outlier bit
    initial_segment_length = Q * l_bit
    test_segment_length = K * l_bit
    full_segment_length = initial_segment_length + test_segment_length
    discard_bit_length = n - full_segment_length
    initial_segment = e >> (test_segment_length + discard_bit_length)
    test_segment = (e - (initial_segment << (test_segment_length + discard_bit_length))) >> discard_bit_length

    # get L-bit last occurrence initial table
    last_occurrence_table = L_bit_last_occurrence(initial_segment, initial_segment_length, l_bit)

    # Accumulating log2 sum of all the differences detected in the Test segment
    sum_log2 = accumulate_log2_sum(test_segment, test_segment_length, l_bit, last_occurrence_table, Q+1)

    # Compute the test statistic
    fn = sum_log2/K

    # Compute P-value
    expected_value, variance = get_mean_and_variance(l_bit)
    p = erfc(abs(fn - expected_value)/(sqrt(2*variance)))
    if p < 0.01:
        r = 'False'
    else:
        r = 'True'
    return l_bit, Q, K, fn, p, r


if __name__ == '__main__':
    print("Randomness_tests")
    # print(total_num_of_runs(619))
    # e = 0b01011010011101010111
    # n = 20
    # mus_test(e, n)

    e = [0xd9aafb948dde47a8,
         0xf3413d481fb7a355,
         0x387390d5c008bdee,
         0x0a3e53de6b973a2e,
         0x1d5dbd50990a69c3,
         0x35d49afaabbcf8c6,
         0x15e5d896e8b49931,
         0xf86ecc8e02d713df,
         0xa9b12767c30d17e8,
         0x3f2b355b951327cc]

    n = 16*4
    for i in e:
        print(frequency_test(i, n))
