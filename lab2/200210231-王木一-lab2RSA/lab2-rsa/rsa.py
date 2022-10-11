# from Crypto.Util import number
import math
import random


def fast_exp_mod(a, b, p):
    '''快速幂运算'''
    y = 1
    while True:
        if b == 0:
            return y
        while b > 0 and b % 2 == 0:
            a = (a ** 2) % p
            b /= 2
        b -= 1
        y = (a * y) % p


def witness(a, n):
    '''miller-rabin核心'''
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


def miller_rabin(n):
    if n == 2:
        return True
    if n < 2 or n % 2 == 0:
        return False
    for i in range(0, random.randint(10, 20)):
        a = random.randint(2, n - 2)
        if not witness(a, n):
            return False
    return True

class RSA:

    def __init__(self):
        self.ciphertext = None
        self.plaintext = None
        self.pub_key = None
        self.pvt_key = None

    def plaintext_process(self):
        '''明文编码'''
        plain_path = input('请输入要加密的明文地址:')
        self.plaintext = []
        cnt = 0
        with open(plain_path, mode='r') as plain:
            line = plain.read()
            print(f'待加密的明文为: {line}')

        with open(plain_path, mode='r') as plain:
            while True:
                c = plain.read(1)
                if not c:
                    break
                cnt += 1
                if cnt == 1:
                    upper = (ord(c) - 32) * 100
                elif cnt == 2:
                    self.plaintext.append(upper + ord(c) - 32)
                    cnt = 0
            if cnt == 1:
                self.plaintext.append(upper + ord('X') - 32)
        plaintext_str = self._toNdigit(self.plaintext, 4)
        print('明文编码结果: ' + ''.join(plaintext_str))

    def encrypt(self):
        '''加密'''
        e = self.pub_key[0]
        n = self.pub_key[1]
        self.ciphertext = []
        for num in self.plaintext:
            self.ciphertext.append(fast_exp_mod(num, e, n))

        ciphertext_str = self._toNdigit(self.ciphertext, 8)
        print('明文加密结果: ' + ''.join(ciphertext_str))

        cipher_path = input('请输入地址以保存密文:')
        with open(cipher_path, mode='w') as cipher:
            cipher.write(''.join(ciphertext_str))

    def decrypt(self):
        '''解密'''
        d = self.pvt_key[0]
        n = self.pvt_key[1]
        s = ''
        ciphertext = []
        cipher_path = input('请输入待解密的密文地址:')
        with open(cipher_path, mode='r') as cipher:
            while True:
                num = cipher.read(8)
                if not num:
                    break
                ciphertext.append(int(num))

        for num in ciphertext:
            de = fast_exp_mod(num, d, n)
            c2 = de % 100
            c1 = de // 100
            s = s + chr(c1 + 32) + chr(c2 + 32)
        print('密文解密结果: ' + s)
        decrypted_path = input('请输入地址以保存已解密的明文:')
        with open(decrypted_path, mode='w') as decrypted:
            decrypted.write(s)

    def _toNdigit(self, lists, n):
        strlist = []
        for num in lists:
            length = len(str(num))
            strlist.append((n - length) * '0' + str(num))
        return strlist

    def key_gen(self):
        '''密钥生成'''
        while True:
            # p = number.getPrime(14)
            # q = number.getPrime(14)
            # if 10000 > p != q < 10000:
            #     break
            p = random.randint(8193, 9999)
            q = random.randint(8193, 9999)
            if miller_rabin(p) and miller_rabin(q) and p != q:
                break

        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = self.get_pubkey(phi_n)
        d = self.get_pvtkey(e, phi_n)
        self.pub_key = [e, n]
        self.pvt_key = [d, n]

        print(f'选取的大素数p, q: {p, q}')
        print(f'两数之积n: {n}, phi_n: {phi_n}')
        print(f'公钥[e, n]: {self.pub_key}')
        print(f'私钥[d, n]: {self.pvt_key}')

        key_path = input('请输入地址以保存密钥:')
        with open(key_path, mode='w') as key:
            key.write('public key [e, n]:' + str(self.pub_key) + '\n')
            key.write('private key [d, n]:' + str(self.pvt_key) + '\n')

    def get_pubkey(self, phi_n):
        '''生成公钥'''
        while True:
            e = random.randint(2, phi_n - 1)
            # if number.isPrime(e) and math.gcd(e, phi_n) == 1:
            if miller_rabin(e) and math.gcd(e, phi_n) == 1:
                break

        return e

    def get_pvtkey(self, e, phi_n):
        '''生成私钥（扩展欧几里德算法)'''
        old_s, s = 1, 0
        old_t, t = 0, 1
        old_r, r = phi_n, e
        while r != 0:
            q = old_r // r
            old_r, r = r, old_r % r
            old_s, s = s, old_s - q * s
            old_t, t = t, old_t - q * t
        if old_t < 0:
            return phi_n + old_t
        else:
            return old_t


if __name__ == '__main__':
    print('---------RSA加密算法演示脚本---------')
    if input('是否开始生成密钥, 1-开始 0-退出:') == '1':
        rsa = RSA()
        print('【密钥生成】')
        rsa.key_gen()
        print('【加解密演示】')
        rsa.plaintext_process()
        rsa.encrypt()
        if input('是否进行解密, 1-解密 0-退出:') == '1':
            rsa.decrypt()
    print('演示结束')



