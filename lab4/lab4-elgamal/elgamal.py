import math
import random
import string

def fast_exp_mod(a, b, p):
    '''
    快速幂运算
    :return: a^b mod p
    '''
    y = 1
    while True:
        if b == 0:
            return y
        while b > 0 and b % 2 == 0:
            a = (a ** 2) % p
            b /= 2
        b -= 1
        y = (a * y) % p


def euclid_exd(e, n):
    '''
    扩展欧几里德算法
    :return: e^(-1) mod n
    '''
    old_s, s = 1, 0
    old_t, t = 0, 1
    old_r, r = n, e
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r % r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    if old_t < 0:
        return n + old_t
    else:
        return old_t

def euclid(a, b):
    '''
    gcd算法
    a >= b
    :return: gcd(a, b)
    '''
    old_r, r = a, b
    while r:
        q = old_r % r
        old_r = r
        r = q
    return old_r

def modify(massage):
    '''
    篡改消息
    :return: 篡改后
    '''
    return massage - random.randint(1, massage-1)

def witness(a, n):
    '''
    miller-rabin核心
    '''
    m = n - 1
    j = 0
    while m % 2 == 0:
        m /= 2
        j += 1
    x = fast_exp_mod(a, m, n)
    if x == 1 or x == n - 1:
        return True

    j -= 1
    while j > 0:
        x = fast_exp_mod(x, 2, n)
        if x == n - 1:
            return True
        j -= 1
    return False

def get_pri_root(n):
    '''
    获得n的本原根(n为素数）
    :return: n的本原根
    '''
    while True:
        r = random.randint(1, n-1)
        if fast_exp_mod(r, n-1, n) == 1:
            for i in range(1, n-1):
                if fast_exp_mod(r, i, n) == 1:
                    break
                else:
                    return r


def miller_rabin(n):
    '''
    判断n是否为素数
    '''
    if n == 2:
        return True
    if n < 2 or n % 2 == 0:
        return False
    for i in range(0, random.randint(10, 20)):
        a = random.randint(2, n - 2)
        if not witness(a, n):
            return False
    return True

class ElGamal:
    def __init__(self):
        self.p = None
        self.g = None
        self.pr_x = None
        self.pu_y = None
        self.k = None
        self.singed = None
        pass

    def gen_key(self):
        while True:
            self.p = random.randint(8193, 9999)
            if miller_rabin(self.p):
                break
        self.g = get_pri_root(self.p)
        self.pr_x = random.randint(2, self.p-2)
        self.pu_y = fast_exp_mod(self.g, self.pr_x, self.p)
        # print(self.p, self.g, self.pr_x, self.pu_y)
        print(f"公钥(p, g, y):{self.p},{self.g},{self.pu_y}. 私钥(x):{self.pr_x}")
        pass

    def sign(self, massage):
        while True:
            self.k = random.randint(1, self.p-1)
            if euclid(self.p-1, self.k) == 1:
                break
        r = fast_exp_mod(self.g, self.k, self.p)
        k_inverse = euclid_exd(self.k, self.p-1)
        s = (k_inverse * (massage - self.pr_x * r)) % (self.p-1)
        self.singed = (r, s)
        print(f"公钥(p, g, y):{self.p},{self.g},{self.pu_y}. 私钥x:{self.pr_x}. 秘密随机数k:{self.k}")
        print(f"签名信息(r, s):{self.singed}")
        pass

    def verify(self, massage):
        r, s = self.singed
        a = (fast_exp_mod(self.pu_y, r, self.p) * fast_exp_mod(r, s, self.p)) % self.p
        b = fast_exp_mod(self.g, massage, self.p)
        if a == b:
            print(f"y^r*r^s mod p = {a}, g^m mod p = {b}")
            return True
        else:
            print(f"y^r*r^s mod p = {a}, g^m mod p = {b}")
            return False
        pass

if __name__ == "__main__":
    print("-----ElGamal数字签名演示-----")
    elgamal = ElGamal()
    print("->【密钥生成】")
    elgamal.gen_key()
    print("->【签名和验证】")
    massage = input("请输入需要签名的消息:")
    massage = int(massage)
    for i in range(2):
        print(f"--->【第{i+1}次签名与验证】")
        print("首先Alice进行签名")
        elgamal.sign(massage)
        if input("是否让Bob进行验证? 1-开始 0-退出:") == '1':
            if elgamal.verify(massage):
                print("***验证通过:)***")
            else:
                print("***验证失败:(***")
    if input("是否进行消息篡改实验? 1-开始 0-退出:") == '1':
        print("->【消息篡改】")
        new_massage = modify(massage)
        print("--->首先Alice进行签名")
        elgamal.sign(massage)
        print("--->中间人篡改消息")
        print(f"原消息：{massage}, 篡改后：{new_massage}")
        print("--->Bob验证篡改后的消息")
        if elgamal.verify(new_massage):
            print("***验证通过:)***")
        else:
            print("***验证失败:(***")
    print("演示结束")



