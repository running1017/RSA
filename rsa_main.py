# -*- coding: utf-8 -*-
"""
Created on Wed Jul  3 13:46:34 2019
RSAで暗号化するデモ
@author: R20979
"""

import rsa_tools

p = (2**148 + 1)//17
q = 2**521 - 1 # でかいメルセンヌ素数
e = 65537

# 鍵生成
pk, sk = rsa_tools.gen_key(e, p, q)

# 鍵表示
print("public_key =\n  {}".format(pk))
print("secret_key =\n  {}\n".format(sk))

# 暗号化したい文字列
text = "<h1>テキストの見出しです</h1>\n<p>テキストの中身です。こんにちは(^_^)。<\p>"
print(text)

# 秘密鍵で暗号化
cipher = rsa_tools.text_encrypt(text, sk)

# 暗号文を表示
print("\ncipher = \n[" + ',\n'.join(map(str, cipher)) + ']\n')

# 公開鍵で復号
dec_text = rsa_tools.text_decrypt(cipher, pk)
print(dec_text)
