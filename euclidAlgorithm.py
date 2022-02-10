import time


def swap(a, b):
    c = a
    a = b
    b = c
    return a, b


def find_gcd(a, b):
    if a < b:
        a, b = swap(a, b)
    r = a % b
    if r == 0:
        return b
    else:
        return find_gcd(b, r)


def extended_euclid(m, b):
    A = [1, 0, m]
    B = [0, 1, b]
    return find_multiplicative_inverse(A, B)


def find_multiplicative_inverse(A, B):
    if B[2] == 0:
        print('no inverse')
        return A[2]
    elif B[2] == 1:
        print(f'{B[1]} is the multiplicative inverse')
        return B[1]
    else:
        q = abs(int(A[2]/B[2]))
        T = [A[0]-q*B[0], A[1]-q*B[1], A[2]-q*B[2]]
        A = B
        B = T
        print(q, A, B)
        return find_multiplicative_inverse(A, B)


if __name__ == '__main__':
    # a, b = 550, 1759
    # time_start = time.time()
    # gcd = find_gcd(a, b)
    # time_stop = time.time()
    # print(f'the great common divisor of {a} and {b} is {gcd}')
    # print(f'time spend is {time_stop-time_start} seconds')
    # m, b = 1759, 550
    # extended_euclid(m, b)
    # a = b'02'
    # b = b'87'
    # m = 0b100011011
    # s = 0b100001110
    a = 0x5f
    b = 0x56
    print(a-b)
    # 0b01101110
    # print(int(m))
    # print(int(a, 16)*int(b, 16))
    # extended_euclid(int(m), int(a, 16)*int(b, 16))
    t = "hello"
    print(t.encode('utf-8').hex())

