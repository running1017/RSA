# -*- coding: utf-8 -*-
"""
Created on Thu Jul  4 08:20:26 2019

@author: R20979
"""

import rsa_tools
import tkinter
import re, pickle
from pathlib import Path

# key入力画面
def input_key():
    root = tkinter.Tk()

    root.title("Input Window")

    # 入力ボックス
    editbox = tkinter.Entry(width=50)
    editbox.pack()

    # 正規表現パターン
    p = r'[ |\n]*\(\d+[,|\n| ]+\d+\)[ |\n]*'

    # 登録ボタンが押されたときの動作
    def button_clicked(event):
        global str_key
        key = editbox.get()
        m = re.match(p, key)
        if m and len(key)==m.end():
            str_key = key
            root.destroy()
        else:
            editbox.delete(0, tkinter.END)
            print("not match")

    button = tkinter.Button(text='登録')
    button.bind("<Button-1>", button_clicked)
    button.pack()

    root.mainloop()

# str_keyをmy_keyに
def str2tuple(string_key):
    str_list = re.split(r'[,|\n| ]+', string_key.strip('()[]'))
    return tuple(map(int, str_list))

# 暗号化・復号化画面
def main_window(my_key):
    root = tkinter.Tk()

    root.title("Main Work")

    # 入力ボックス
    inputbox = tkinter.Text(font=("MS Pゴシック", 10))
    # 出力ボックス
    outputbox = tkinter.Text(state='disabled', font=("MS Pゴシック", 10))

    # ボタン
    enc_button = tkinter.Button(text='送信する')
    preview_button = tkinter.Button(text='プレビュー')
    paste_button = tkinter.Button(text='受信から貼り付け')
    clear_button = tkinter.Button(text='クリア')
    dec_button = tkinter.Button(text='受信した')
    copy_button = tkinter.Button(text='送信へコピー')

    # メニュー
    input_menu = tkinter.Menu(tearoff=0)
    input_menu.add_command(label="部分暗号化")

    # encボタンの動作
    def enc_clicked(event):
        send_cipher = rsa_tools.partially_encrypt(inputbox.get('1.0', 'end -1c'), my_key)
        outputbox.configure(state='normal')
        outputbox.delete('1.0', 'end')
        outputbox.insert('1.0', send_cipher)
        outputbox.configure(state='disabled')

    # decボタンの動作
    def dec_clicked(event):
        try:
            cipher = inputbox.get('1.0', 'end -1c')
            receive_text = rsa_tools.partially_decrypt(cipher, my_key)
        except:
            receive_text = "復号化できませんでした"

        outputbox.configure(state='normal')
        outputbox.delete('1.0', 'end')
        outputbox.insert('1.0', receive_text)
        outputbox.configure(state='disabled')

    # pasteボタンの動作
    def paste_clicked(event):
        text = tkinter.Text().clipboard_get()
        inputbox.delete('1.0', 'end')
        inputbox.insert('1.0', text)

    # copyボタンの動作
    def copy_clicked(event):
        text = outputbox.get('1.0', 'end -1c')
        tkinter.Text().clipboard_clear()
        tkinter.Text().clipboard_append(text)

    # clearボタンの動作
    def clear_clicked(event):
        inputbox.delete('1.0', 'end')
        outputbox.configure(state='normal')
        outputbox.delete('1.0', 'end')
        outputbox.configure(state='disabled')

    # previewボタンの動作
    def preview_clicked(event):
        send_preview = rsa_tools.dec_preview(inputbox.get('1.0', 'end -1c'))
        outputbox.configure(state='normal')
        outputbox.delete('1.0', 'end')
        outputbox.insert('1.0', send_preview)
        outputbox.configure(state='disabled')

    # 選択されているところを[]で囲う
    def partially_select():
        try:
            first = inputbox.index('sel.first')
            last = inputbox.index('sel.last')
            del_last = inputbox.index('sel.last')
        except:
            first = '1.0'
            last = 'end -1c'
            del_last = 'end'

        text = '[' + inputbox.get(first, last) + ']'
        inputbox.delete(first, del_last)
        inputbox.insert(first, text)

    # inputboxの右クリック動作
    def show_menu(event):
        input_menu.entryconfigure("部分暗号化", command=partially_select)
        input_menu.tk.call("tk_popup", input_menu, event.x_root, event.y_root)

    # オブジェクトの描画
    inputbox.grid(row=0, column=0, columnspan=6, sticky='we')
    paste_button.grid(row=1, column=0, sticky='we')
    dec_button.grid(row=1, column=1, sticky='we')
    preview_button.grid(row=1, column=2, sticky='we')
    clear_button.grid(row=1, column=3, sticky='we')
    enc_button.grid(row=1, column=4, sticky='we')
    copy_button.grid(row=1, column=5, sticky='we')
    outputbox.grid(row=2, column=0, columnspan=6, sticky='we')

    # 関数のバインド
    inputbox.bind("<Button-3>", show_menu)
    inputbox.bind("<Control-KeyPress-e>", lambda e: partially_select())
    paste_button.bind("<Button-1>", paste_clicked)
    dec_button.bind("<Button-1>", dec_clicked)
    preview_button.bind("<Button-1>", preview_clicked)
    clear_button.bind("<Button-1>", clear_clicked)
    enc_button.bind("<Button-1>", enc_clicked)
    copy_button.bind("<Button-1>", copy_clicked)

    root.mainloop()

if __name__ == '__main__':
    key = list(Path('.').glob('*.key'))
    if len(key)==0:
        input_key()
        my_key = str2tuple(str_key)
        with open('./my.key', 'wb') as f:
            pickle.dump(my_key, f)
    else:
        with key[0].open('rb') as f:
            my_key = pickle.load(f)
    main_window(my_key)

