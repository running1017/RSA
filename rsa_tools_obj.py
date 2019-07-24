# -*- coding: utf-8 -*-
"""
Created on Tue Jul  2 15:30:57 2019

@author: R20979
"""

from hashlib import sha256
import re
import random

str_code = 'utf-8'
endian = 'big'
hash_func = sha256
JPN_bytes = 3
max_len = 10

class Basic_RSA():
    # 最大公約数を計算
    @classmethod
    def gcd(cls, a, b):
        while b:
            a, b = b, a % b
        return a

    # 最小公倍数を計算
    @classmethod
    def lcm(cls, x, y):
        return x * y // cls.gcd(x, y)

    # 拡張ユークリッドの互除法
    @classmethod
    def ex_euclid(cls, x, y):
        c0, c1 = x, y
        a0, a1 = 1, 0
        b0, b1 = 0, 1

        while c1 != 0:
            m = c0 % c1
            q = c0 // c1

            c0, c1 = c1, m
            a0, a1 = a1, (a0 - q * a1)
            b0, b1 = b1, (b0 - q * b1)

        return c0, a0, b0

    # Miller-Rabinによる素数判定
    @classmethod
    def is_prime(cls, n, k):
        if n == 2: return True
        if n == 1 or n & 1 == 0: return False

        d = (n-1) >> 1
        while d & 1 == 0:
            d >>= 1

        for k in range(k):
            a = random.randint(1, n-1)
            t = d
            y = pow(a, t, n)
            while t != n-1 and y != 1 and y != n- 1:
                y = (y * y) % n
                t <<= 1

            if y != n - 1 and t & 1 == 0:
                return False

        return True

    # 鍵生成
    @classmethod
    def gen_key(cls, e, p, q):
        pub_key = (e, p*q)
        l = cls.lcm(p-1, q-1)
        _, a, _ = cls.ex_euclid(e, l)
        sec_key = (a%l, p*q)
        return pub_key, sec_key

    # 暗号化・復号化
    @classmethod
    def crypt(cls, num, key):
        e, n = key
        return pow(num, e, n)

class Str_Crypt():
    def __init__(self, my_key):
        self.crypt = lambda num: Basic_RSA.crypt(num, my_key)

    # strをintに
    @classmethod
    def str2int(cls, text):
        bytes_text = text.encode(str_code)
        return int.from_bytes(bytes_text, endian)

    # intをstrに
    @classmethod
    def int2str(cls, num):
        bytes_text = num.to_bytes(max_len*JPN_bytes, endian)
        return bytes_text.decode(str_code).replace('\x00', '')

    # strをtupleに
    @classmethod
    def str2tuple(cls, string):
        str_list = re.split(r'[,|\n| ]+', string.strip('()[]'))
        return tuple(map(int, str_list))

    # 文字列を分割して暗号化
    def text_encrypt(self, plaintext):
        text_len = len(plaintext)
        sub_texts = [plaintext[i:i+max_len] for i in range(0, text_len, max_len)]
        return [self.crypt(self.str2int(text)) for text in sub_texts]

    # 分割された暗号を文字列に復号
    def text_decrypt(self, c_list):
        sub_texts = [self.int2str(self.crypt(cipher)) for cipher in c_list]
        return ''.join(sub_texts)

    partially_sub_enc = lambda m: '[' + ','.join(map(str, text_encrypt(m.group().strip('[]「」')))) + ']'

    # []と「」で囲まれた部分だけ暗号化
    def partially_encrypt(self, text, enc=partially_sub_enc):
        pattern = r'[\[|「][^\[\]「」]*[\]|」]'
        i = 0
        partially_encrypted = ''
        for m in re.finditer(pattern, text):
            partially_encrypted += text[i: m.start()]
            enc_text = enc(m)
            partially_encrypted += enc_text
            i = m.end()
        partially_encrypted += text[i: len(text)]
        return partially_encrypted

    # 復号化したときのプレビュー
    def dec_preview(self, text):
        return self.partially_encrypt(text, enc=lambda m: m.group().strip('[]「」'))

    # []で囲まれた部分だけ復号化
    def partially_decrypt(self, text):
        pattern = r'\[[^\[\]]*\]'
        i = 0
        partially_decrypted = ''
        for m in re.finditer(pattern, text):
            partially_decrypted += text[i: m.start()]
            dec_text = self.text_decrypt(self.str2tuple(m.group()))
            partially_decrypted += dec_text
            i = m.end()
        partially_decrypted += text[i: len(text)]
        return partially_decrypted

class Signature_RSA():
    def __init__(self, my_key):
        self.crypt = lambda num: Basic_RSA.crypt(num, my_key)

    # 電子署名作成
    def e_sign(self, plaintext):
        hash_num = self.get_hash(plaintext)
        return self.crypt(hash_num)

    # 電子署名の検証
    # Accept=>True, Reject=>False
    def verify_signature(self, plaintext, signature):
        hash_num = self.get_hash(plaintext)
        dec_hash = self.crypt(signature)
        return hash_num == dec_hash

    # hash値の取得
    def get_hash(self, text):
        hash_key = hash_func(text.encode(str_code))
        return int.from_bytes(hash_key.digest(), endian)

    # 検証結果をACCEPTかREJECTに
    def verify(self, check):
        if check:
            return 'ACCEPT'
        else:
            return 'REJECT'
