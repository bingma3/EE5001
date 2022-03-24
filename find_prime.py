import time


def is_prime(num, p_num):
    if len(p_num) > 0:
        if num <= p_num[-1]:
            return False
        for i in p_num:
            if num % i == 0:
                return False
        return True
    else:
        if num == 1:
            return False
        if num == 2:
            return True


n = 100000

prime = []
new_prime = []
data_update = False
with open('prime.txt', 'r') as f:
    lines = f.readlines()
    if lines:
        for line in lines:
            prime.append(int(line.rstrip()))
cnt = 2
start_time = time.time()
while cnt <= n:
    if len(prime) > 0 and n <= prime[-1]:
        for i in prime:
            if i <= n:
                new_prime.append(i)
        break
    if is_prime(cnt, prime):
        data_update = True
        new_prime.append(cnt)
        prime.append(cnt)
    cnt += 1
end_time = time.time()
if data_update:
    print(f'find {len(prime)} Prime number in {n} use {end_time-start_time} second')
    with open('prime.txt', 'a') as f:
        for i in new_prime:
            f.write(str(i)+'\n')
    if len(prime) <= 50:
        print(prime)
    else:
        print(prime[:25], prime[-25:])
else:
    print(f'find {len(new_prime)} Prime number in {n} use {end_time-start_time} second')
    if len(new_prime) <= 50:
        print(new_prime)
    else:
        print(new_prime[:24], new_prime[-24:])



