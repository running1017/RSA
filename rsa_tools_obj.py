# -*- coding: utf-8 -*-
"""
Created on Tue Jul  2 15:30:57 2019

@author: R20979
"""

import base64
import datetime
import random
import re
from hashlib import sha256

str_code = 'utf-8'
hash_func = sha256


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
    def twin_prime(cls, n_digits):
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
    def gen_key(cls, n_digits):
        e = 65537
        p, q = cls.twin_prime(n_digits)

        pub_key = [e, p*q]

        l = cls.lcm(p-1, q-1)
        _, a, _ = cls.ex_euclid(e, l)
        sec_key = [a%l, p*q]
        return pub_key, sec_key

    # 暗号化・復号化
    @classmethod
    def crypt(cls, num, key):
        e, n = key
        return pow(num, e, n)


# メタデータが扱えるKeyクラスの定義
class Key():
    def __init__(self, info):
        self.update(info)

    def update(self, info):
        self.key = info['key']
        self.n_digits = info['n_digits']
        self.is_public = info['is_public']
        self.from_name = info['from']
        self.destination_name = info['destination']
        self.creation_date = datetime.date.fromisoformat(info['creation_date'])

    def dump(self):
        return {
            'key': self.key,
            'n_digits': self.n_digits,
            'is_public': self.is_public,
            'from': self.from_name,
            'destination': self.destination_name,
            'creation_date': self.creation_date.isoformat()
        }


class EX_RSA():
    def __init__(self, n_digits):
        self.endian = 'big'
        self.n_digits = n_digits

    def int2byte(self, num):
        return num.to_bytes(self.n_digits//8, self.endian)

    # Base64でintをエンコード
    def int_b64encode(self, num):
        byted = self.int2byte(num)
        return base64.b64encode(byted).decode()

    # Base64でデコードしてintに
    def b64_decode(self, b64):
        byted = base64.b64decode(b64.encode())
        return int.from_bytes(byted, self.endian)

    # Base85でintをエンコード
    def int_b85encode(self, num):
        byted = self.int2byte(num)
        return base64.b85encode(byted).decode()

    # Base85でデコードしてintに
    def b85_decode(self, b85):
        byted = base64.b85decode(b85.encode())
        return int.from_bytes(byted, self.endian)


class Str_Crypt():
    def __init__(self, my_key):
        self.crypt = lambda num: Basic_RSA.crypt(num, my_key.key)
        self.n_digits = my_key.n_digits

    # strをtupleに
    @classmethod
    def str2tuple(cls, string):
        str_list = re.split('[,\n ]+', string.strip('()[]'))
        return str_list

    # 文字列を分割して暗号化
    def text_encrypt(self, plaintext, c_type=lambda x: x):
        byted_text = plaintext.encode(str_code)
        text_len = len(byted_text)
        max_len = self.n_digits//8
        sub_texts = [byted_text[i:i+max_len] for i in range(0, text_len, max_len)]
        sub_cipher = lambda t: c_type(self.crypt(int.from_bytes(t, 'little')))
        return [sub_cipher(text) for text in sub_texts]

    # 分割された暗号を文字列に復号
    def text_decrypt(self, c_list, c_type=lambda x: int(x)):
        sub_text = lambda c: self.crypt(c_type(c)).to_bytes(self.n_digits//8+1, 'little')
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
