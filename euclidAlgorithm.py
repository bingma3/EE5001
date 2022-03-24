import time


class EUCLID_ALGORITHM:
    def __init__(self):
        """
            Find the multiplicative inverse by using the Extended Euclid Algorithm

            use func: extended_euclid(m, b)
                where:
                    m = modulo
                    b = integer number

        """
        print('Find the multiplicative inverse by using the Extended Euclid Algorithm')

    @staticmethod
    def swap(x, y):
        c = x
        x = y
        y = c
        return x, y

    def find_gcd(self, x, y):
        if x < y:
            x, y = self.swap(x, y)
        r = x % y
        if r == 0:
            return y
        else:
            return self.find_gcd(y, r)

    def extended_euclid(self, m, b):
        A = [1, 0, m]
        B = [0, 1, b]
        return self.find_multiplicative_inverse(A, B)

    def find_multiplicative_inverse(self, A, B):
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
            return self.find_multiplicative_inverse(A, B)

    @staticmethod
    def mod(m, b):
        A = [1, 0, m]
        B = [0, 1, b]
        q = abs(int(A[2] / B[2]))
        T = [A[0] - q * B[0], A[1] - q * B[1], A[2] - q * B[2]]
        A = B
        B = T
        q = abs(int(A[2] / B[2]))
        return A[2] - q * B[2]


if __name__ == '__main__':
    # a, b = 550, 1759
    # time_start = time.time()
    euclid = EUCLID_ALGORITHM()
    # gcd = mod.find_gcd(a, b)
    # time_stop = time.time()
    # print(f'the great common divisor of {a} and {b} is {gcd}')
    # print(f'time spend is {time_stop-time_start} seconds')
    # m, b = 1759, 555
    m, b = 8, 10
    outcome = euclid.extended_euclid(m, b)
    print(euclid.mod(m, b))
    print(outcome)




