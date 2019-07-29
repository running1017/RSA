# -*- coding: utf-8 -*-
"""
Created on Thu Jul  4 08:20:26 2019

@author: R20979
"""

import tkinter as tk
from tkinter import ttk

import rsa_tools_obj


# ウィンドウ全体の処理
class Main_Window(ttk.Notebook):
    def __init__(self, master=None):
        super().__init__(master)
        self.master.title('main job')

        # メインタブの作成
        main_tab = ttk.Frame(self)
        self.add(main_tab, text="crypt", padding=3)
        key_set = Main_Tab(master=main_tab).key_set

        # キータブの作成
        key_tab = ttk.Frame(self)
        self.add(key_tab, text="key", padding=3)
        Key_Tab(master=key_tab, key_set=key_set)

        # Main_Windowの描画
        self.pack(expand=1, fill='both')


# メインタブの処理
class Main_Tab(ttk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_widgets()
        self.key_set(None)

        # 暗号文のコードはBase85
        self.encoder = rsa_tools_obj.EX_RSA().int_b85encode
        self.decoder = rsa_tools_obj.EX_RSA().b85_decode

    # 鍵の登録
    def key_set(self, my_key):
        self.cryptor = rsa_tools_obj.Str_Crypt(my_key)

    # ウィジェットの作成
    def create_widgets(self):
        input_frame = ttk.Frame(self.master)
        button_frame = ttk.Frame(self.master)
        output_frame = ttk.Frame(self.master)

        self.create_input_frame(input_frame)
        self.create_button_frame(button_frame)
        self.create_output_frame(output_frame)

        input_frame.grid(row=0, column=0, sticky='nsew')
        button_frame.grid(row=1, column=0, sticky='nsew')
        output_frame.grid(row=2, column=0, sticky='nsew')

        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure((0, 2), weight=1)

    # 入力ボックス関連フレームの作成
    def create_input_frame(self, frame):
        self.input_box = tk.Text(frame, font=("MS Pゴシック", 12), height=8)
        paste_button = ttk.Button(frame, text="貼り付け")
        scrollbar = tk.Scrollbar(frame, command=self.input_box.yview)
        self.input_menu = tk.Menu(frame, tearoff=0)
        self.input_menu.add_command(label="部分暗号化    Ctrl+e")

        self.input_box.bind("<Button-3>", self.input_show_menu)
        self.input_box.bind("<Control-KeyPress-e>", lambda e: self.partially_select())
        self.input_box["yscrollcommand"] = scrollbar.set
        paste_button.bind("<Button-1>", self.paste_clicked)

        self.input_box.grid(row=0, column=0, sticky='nsew')
        paste_button.grid(row=0, column=0, sticky='se')
        scrollbar.grid(row=0, column=1, sticky='ns')

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

    # ボタン関連フレームの作成
    def create_button_frame(self, frame):
        dec_button = ttk.Button(frame, text="受信した")
        preview_button = ttk.Button(frame, text="プレビュー")
        clear_button = ttk.Button(frame, text="クリア")
        enc_button = ttk.Button(frame, text="送信する")

        dec_button.bind("<Button-1>", self.dec_clicked)
        preview_button.bind("<Button-1>", self.preview_clicked)
        clear_button.bind("<Button-1>", self.clear_clicked)
        enc_button.bind("<Button-1>", self.enc_clicked)

        dec_button.grid(row=0, column=0, sticky='ew')
        preview_button.grid(row=0, column=1, sticky='ew')
        clear_button.grid(row=0, column=2, sticky='ew')
        enc_button.grid(row=0, column=3, sticky='ew')

        frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

    # 出力ボックス関連フレームの作成
    def create_output_frame(self, frame):
        self.output_box = tk.Text(frame, state='disabled', font=("MS Pゴシック", 12), height=8)
        copy_button = ttk.Button(frame, text="コピー")
        scrollbar = ttk.Scrollbar(frame, command=self.output_box.yview)

        self.output_box["yscrollcommand"] = scrollbar.set
        copy_button.bind("<Button-1>", self.copy_clicked)

        self.output_box.grid(row=0, column=0, sticky='nsew')
        copy_button.grid(row=0, column=0, sticky='se')
        scrollbar.grid(row=0, column=1, sticky='ns')

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

    # 入力ボックスにメニューを表示
    def input_show_menu(self, event):
        self.input_menu.entryconfigure("部分暗号化    Ctrl+e", command=self.partially_select)
        self.input_menu.tk.call("tk_popup", self.input_menu, event.x_root, event.y_root)

    # 選択されているところを[]で囲う
    def partially_select(self):
        try:
            first = self.input_box.index('sel.first')
            last = self.input_box.index('sel.last')
            del_last = self.input_box.index('sel.last')
        except:
            first = '1.0'
            last = 'end -1c'
            del_last = 'end'

        text = '[' + self.input_box.get(first, last) + ']'
        self.input_box.delete(first, del_last)
        self.input_box.insert(first, text)

    # 入力ボックスの内容を暗号化して出力ボックスに表示
    def enc_clicked(self, event):
        send_cipher = self.cryptor.partially_encrypt(self.input_box.get('1.0', 'end -1c'), self.encoder)
        self.output_box.configure(state='normal')
        self.output_box.delete('1.0', 'end')
        self.output_box.insert('1.0', send_cipher)
        self.output_box.configure(state='disabled')

    # 入力ボックスの内容を復号化して出力ボックスに表示
    def dec_clicked(self, event):
        try:
            cipher = self.input_box.get('1.0', 'end -1c')
            receive_text = self.cryptor.partially_decrypt(cipher, self.decoder)
        except ValueError:
            receive_text = "復号化できませんでした"

        self.output_box.configure(state='normal')
        self.output_box.delete('1.0', 'end')
        self.output_box.insert('1.0', receive_text)
        self.output_box.configure(state='disabled')

    # クリップボードの内容を入力ボックスに貼り付け
    def paste_clicked(self, event):
        text = tk.Text().clipboard_get()
        self.input_box.delete('1.0', 'end')
        self.input_box.insert('1.0', text)

    # 出力ボックスの内容をクリップボードにコピー
    def copy_clicked(self, event):
        text = self.output_box.get('1.0', 'end -1c')
        tk.Text().clipboard_clear()
        tk.Text().clipboard_append(text)

    # 入出力ボックスの中身を空にする
    def clear_clicked(self, event):
        self.input_box.delete('1.0', 'end')
        self.output_box.configure(state='normal')
        self.output_box.delete('1.0', 'end')
        self.output_box.configure(state='disabled')

    # 相手が復号化したときのプレビューを表示
    def preview_clicked(self, event):
        send_preview = self.cryptor.dec_preview(self.input_box.get('1.0', 'end -1c'))
        self.output_box.configure(state='normal')
        self.output_box.delete('1.0', 'end')
        self.output_box.insert('1.0', send_preview)
        self.output_box.configure(state='disabled')


# キーの作成・登録をするタブの処理
class Key_Tab(ttk.Frame):
    def __init__(self, master=None, key_set=None):
        super().__init__(master)
        self.key_set = key_set
        self.create_widgets()

    # ウィジェットの作成
    def create_widgets(self):
        current_frame = ttk.Frame(self.master)
        new_frame = ttk.Frame(self.master)

        self.create_current_frame(current_frame)
        self.create_new_frame(new_frame)

        current_frame.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        new_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)

        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure((0, 1), weight=1)

    # 鍵選択関連フレームの作成
    def create_current_frame(self, frame):
        label_frame = ttk.Labelframe(frame, text="現在の通信先")
        key_select = ttk.Combobox(label_frame, state='readonly')

        label_frame.grid(row=0, column=0, sticky='nsew')
        key_select.grid(row=0, column=0, sticky='ew')

        label_frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)

    # 鍵新規作成フレームの作成
    def create_new_frame(self, frame):
        label_frame = ttk.Labelframe(frame, text="新規作成")
        from_label = ttk.Label(label_frame, text="自分の名前")
        from_box = ttk.Entry(label_frame)
        to_label = ttk.Label(label_frame, text="相手の名前")
        to_box = ttk.Entry(label_frame)
        create_button = ttk.Button(label_frame, text="作成")

        label_frame.grid(row=0, column=0, sticky='nsew')
        from_label.grid(row=0, column=0, sticky='w', padx=10, pady=10)
        from_box.grid(row=0, column=1, sticky='ew', padx=10)
        to_label.grid(row=1, column=0, sticky='w', padx=10, pady=10)
        to_box.grid(row=1, column=1, sticky='ew', padx=10)
        create_button.grid(row=2, column=1, sticky='e', padx=10, pady=10)

        label_frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(0, weight=1)
    

if __name__ =='__main__':
    root = tk.Tk()
    Main_Window(root)
    root.update()
    root.minsize(300, 200)
    root.mainloop()
