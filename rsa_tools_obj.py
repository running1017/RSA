# -*- coding: utf-8 -*-
"""
Created on Tue Jul  2 15:30:57 2019

@author: R20979
"""

import base64
import random
import re
from hashlib import sha256

str_code = 'utf-8'
hash_func = sha256
n_digits = 712


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

    # 掛けると2進数でn_digits桁になる素数をランダムに2つ生成
    @classmethod
    def twin_prime(cls):
        p_digits = random.randint(n_digits//10, n_digits-n_digits//10)
        p = cls.search_prime(2**p_digits, 2**(p_digits+1)-1)

        q_min = pow(2, n_digits)//p
        q_max = (pow(2, n_digits+1)-1)//p
        q = cls.search_prime(q_min, q_max)

        return p, q

    @classmethod
    def search_prime(cls, p_min, p_max):
        p = 4

        while(not cls.is_prime(p, 100)):
            p = random.randint(p_min, p_max)

        return p

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


class EX_RSA():
    endian = 'big'

    @classmethod
    def int2byte(cls, num):
        return num.to_bytes(n_digits//8, cls.endian)

    # Base64でintをエンコード
    @classmethod
    def int_b64encode(cls, num):
        byted = cls.int2byte(num)
        return base64.b64encode(byted)

    # Base64でデコードしてintに
    @classmethod
    def b64_decode(cls, b64):
        byted = base64.b64decode(b64)
        return int.from_bytes(byted, cls.endian)

    # Base85でintをエンコード
    @classmethod
    def int_b85encode(cls, num):
        byted = cls.int2byte(num)
        return base64.b85encode(byted)

    # Base85でデコードしてintに
    @classmethod
    def b85_decode(cls, b85):
        byted = base64.b85decode(b85)
        return int.from_bytes(byted, cls.endian)


class Str_Crypt():
    def __init__(self, my_key):
        self.crypt = lambda num: Basic_RSA.crypt(num, my_key)

    # strをtupleに
    @classmethod
    def str2tuple(cls, string):
        str_list = re.split(r'[,|\n| ]+', string.strip('()[]'))
        return tuple(map(int, str_list))

    # 文字列を分割して暗号化
    def text_encrypt(self, plaintext, c_type=lambda x: x):
        byted_text = plaintext.encode(str_code)
        text_len = len(byted_text)
        max_len = n_digits//8
        sub_texts = [byted_text[i:i+max_len] for i in range(0, text_len, max_len)]
        sub_cipher = lambda t: c_type(self.crypt(int.from_bytes(t, 'little')))
        return [sub_cipher(text) for text in sub_texts]

    # 分割された暗号を文字列に復号
    def text_decrypt(self, c_list, c_type=lambda x: x):
        sub_text = lambda c: c_type(self.crypt(c).to_bytes(n_digits//8+1, 'little'))
        sub_byted_texts = [sub_text(cipher) for cipher in c_list]
        byted_texts = b''.join(sub_byted_texts)
        return byted_texts.decode(str_code).replace('\x00', '')

    # 復号化したときのプレビュー
    def dec_preview(self, text, enc=lambda m: m.group().strip('[]「」')):
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

    # []と「」で囲まれた部分だけ暗号化
    def partially_encrypt(self, text, *c_type):
        partially_sub_enc = lambda m:\
            '[' + ','.join(map(str, self.text_encrypt(m.group().strip('[]「」'), *c_type))) + ']'
        return self.dec_preview(text, enc=partially_sub_enc)

    # []で囲まれた部分だけ復号化
    def partially_decrypt(self, text, *c_type):
        pattern = r'\[[^\[\]]*\]'
        i = 0
        partially_decrypted = ''
        for m in re.finditer(pattern, text):
            partially_decrypted += text[i: m.start()]
            dec_text = self.text_decrypt(self.str2tuple(m.group()), *c_type)
            partially_decrypted += dec_text
            i = m.end()
        partially_decrypted += text[i: len(text)]
        return partially_decrypted


# 鍵オブジェクト
class Key_Obj():
    def __init__(self):
        pass

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
        endian = 'big'
        hash_key = hash_func(text.encode(str_code))
        return int.from_bytes(hash_key.digest(), endian)

    # 検証結果を'ACCEPT'か'REJECT'という文字列に
    def verify(self, check):
        if check:
            return 'ACCEPT'
        else:
            return 'REJECT'
