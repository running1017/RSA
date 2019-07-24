# -*- coding: utf-8 -*-
"""
Created on Wed Jul  3 15:53:51 2019
RSAで電子署名するデモ
@author: R20979
"""

import rsa_tools

p = 2**127 - 1 # でかいメルセンヌ素数
q = 2**521 - 1 # でかいメルセンヌ素数
e = 65537

# 鍵生成
pk, sk = rsa_tools.gen_key(e, p, q)

# 鍵表示
print("public_key =\n  {}".format(pk))
print("secret_key =\n  {}\n".format(sk))

# 署名したい文字列
text = "この文章は正しいよ"
print("text =\n" + text + "\n")

# 電子署名
signature = rsa_tools.e_sign(text, sk)
print("signature =\n{}\n".format(signature))

# 公開鍵で電子署名を検証
check1 = rsa_tools.verify_signature(text, signature, pk)
print(text + "\n  is " + rsa_tools.verify(check1))

# 偽造された文字列
forgery_text = "この文章は正しいょ"
check2 = rsa_tools.verify_signature(forgery_text, signature, pk)
print(forgery_text + "\n  is " + rsa_tools.verify(check2))
