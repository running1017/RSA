# -*- coding: utf-8 -*-
"""
Created on Thu Jul  4 08:20:26 2019

@author: R20979
"""

import datetime
import json
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

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
        self.key_set(None) # あとで削除

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
        self.input_box = tk.Text(frame, font=("MS Pゴシック", 12), height=10)
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
        self.output_box = tk.Text(
            frame,
            state='disabled',
            font=("MS Pゴシック", 12),
            height=10
        )
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
        self.input_menu.entryconfigure(
            "部分暗号化    Ctrl+e",
            command=self.partially_select
        )
        self.input_menu.tk.call(
            "tk_popup",
            self.input_menu,
            event.x_root,
            event.y_root
        )

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
        send_cipher = self.cryptor.partially_encrypt(
            self.input_box.get('1.0', 'end -1c'),
            self.encoder
        )
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
        self.pubkeys_dir = Path('./public')
        self.pubkeys_dir.mkdir(exist_ok=True)
        self.my_keys_dir = Path('./.key')
        self.my_keys_dir.mkdir(exist_ok=True)
        self.create_widgets()

    # ウィジェットの作成
    def create_widgets(self):
        current_frame = ttk.Labelframe(self.master, text="現在の通信先")
        new_frame = ttk.Labelframe(self.master, text="新規作成")

        self.create_current_frame(current_frame)
        self.create_new_frame(new_frame)

        current_frame.grid(row=0, column=0, sticky='nsew', padx=10, pady=10)
        new_frame.grid(row=1, column=0, sticky='nsew', padx=10, pady=10)

        self.master.grid_columnconfigure(0, weight=1)
        self.master.grid_rowconfigure((0, 1), weight=1)

    # 鍵選択関連フレームの作成
    def create_current_frame(self, frame):
        # ウィジェットの作成
        self.key_var        = tk.StringVar(frame)
        self.key_select     = ttk.Combobox(frame, textvariable=self.key_var, state='readonly')
        to_label            = ttk.Label(frame, text="通信先:")
        self.to_var         = tk.StringVar(frame)
        to_name_label       = ttk.Label(frame, textvariable=self.to_var)
        creation_label      = ttk.Label(frame, text="作成日:")
        self.date_var       = tk.StringVar(frame)
        creation_date_label = ttk.Label(frame, textvariable=self.date_var)

        # 関数のバインド
        self.key_select.bind("<Button-1>", self.key_select_clicked)
        self.key_select.bind("<<ComboboxSelected>>", self.key_selected)

        # ウィジェットの配置
        self.key_select.grid(row=0, column=0, columnspan=3, sticky='ew', padx=20, pady=10)
        to_label.grid(row=1, column=0, sticky='w', padx=20)
        to_name_label.grid(row=1, column=1, sticky='w', padx=20)
        creation_label.grid(row=2, column=0, sticky='w', padx=20)
        creation_date_label.grid(row=2, column=1, sticky='w', padx=20)

        frame.grid_columnconfigure(2, weight=1)

    # 鍵新規作成フレームの作成
    def create_new_frame(self, frame):
        # ウィジェットの作成
        title_label             = ttk.Label(frame, text="鍵名")
        self.title_box          = ttk.Entry(frame)
        from_label              = ttk.Label(frame, text="自分の名前")
        self.from_box           = ttk.Entry(frame)
        destination_label       = ttk.Label(frame, text="相手の名前")
        self.destination_box    = ttk.Entry(frame)
        pubkeys_dir_label       = ttk.Label(frame, text="公開鍵の保存先")
        pubkeys_dir_frame       = ttk.Frame(frame)
        self.pubkeys_dir_var    = tk.StringVar(pubkeys_dir_frame, value=self.pubkeys_dir.resolve())
        pubkeys_dir_box         = ttk.Entry(
            pubkeys_dir_frame, textvariable=self.pubkeys_dir_var, state='readonly')
        pubkey_extention_label  = ttk.Label(pubkeys_dir_frame, text=".key")
        pubkeys_dir_button      = ttk.Button(pubkeys_dir_frame, text="参照")
        pubkey_explain_label    = ttk.Label(frame, text="※作成した公開鍵を相手に渡してください")
        create_button           = ttk.Button(frame, text="作成")

        # 関数のバインド
        self.title_box.bind("<KeyRelease>", self.pubkeys_dir_update)
        pubkeys_dir_button.bind("<Button-1>", self.pubkeys_dir_select)
        create_button.bind("<Button-1>", self.create_key)

        # ウィジェットの配置
        title_label.grid(row=0, column=0, sticky='w', padx=10, pady=10)
        self.title_box.grid(row=0, column=1, sticky='ew', padx=20)
        from_label.grid(row=1, column=0, sticky='w', padx=10, pady=10)
        self.from_box.grid(row=1, column=1, sticky='ew', padx=20)
        destination_label.grid(row=2, column=0, sticky='w', padx=10, pady=10)
        self.destination_box.grid(row=2, column=1, sticky='ew', padx=20)
        pubkeys_dir_label.grid(row=3, column=0, sticky='w', padx=10, pady=(10, 0))
        pubkeys_dir_frame.grid(row=3, column=1, sticky='ew', padx=20, pady=(10, 0))
        pubkey_explain_label.grid(row=4, column=1, sticky='w', padx=20)
        create_button.grid(row=5, column=1, sticky='e', padx=20, pady=10)

        pubkeys_dir_box.grid(row=0, column=0, sticky='ew')
        pubkey_extention_label.grid(row=0, column=1, sticky='e')
        pubkeys_dir_button.grid(row=0, column=2, sticky='e')

        pubkeys_dir_frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)

    # ./.key/以下の鍵一覧を取得
    def get_keys_list(self):
        return list(self.my_keys_dir.glob("*key"))

    # key_selectのvaluesに現在の鍵のファイル名で更新
    def key_select_clicked(self, event):
        self.keys_list = self.get_keys_list()
        self.key_select['values'] = [key.stem() for key in self.keys_list]

    # key_selectで値を選択したときの動作
    def key_selected(self, event):
        key_index = self.key_select.current()
        key_dir = self.keys_list[key_index]
        with key_dir.open('r') as file:
            self.key_data = rsa_tools_obj.Key(json.load(file))

        self.key_set(self.key_data.key)
        self.to_var = self.key_data.from_name if self.key_data.is_public else self.key_data.destination_name
        self.date_var = self.key_data.creation_date.isoformat()

    # 公開鍵を保存するディレクトリを選択する
    def pubkeys_dir_select(self, event):
        pk_dir = filedialog.askdirectory(initialdir=self.pubkeys_dir)
        self.pubkeys_dir = Path(pk_dir)
        self.pubkeys_dir_update(None)

    # titleが入力されたらpubkeys_dir_boxの値を変える
    def pubkeys_dir_update(self, event):
        title = (self.pubkeys_dir / self.title_box.get()).resolve()
        self.pubkeys_dir_var.set(title)

    # 新規鍵を作成して秘密鍵を./.keyに、公開鍵を./pubkeyに作成
    def create_key(self, event):
        pk, sk = rsa_tools_obj.Basic_RSA.gen_key()

        def addition_info(key):
            return {
                'key': key,
                'from': self.from_box.get(),
                'destination': self.destination_box.get(),
                'creation_date': datetime.date.today().isoformat()
            }

        pk_data = addition_info(pk)
        pk_data['is_public'] = True
        pk_path = self.pubkeys_dir / (self.title_box.get() + '.key')
        with pk_path.open('w') as f:
            json.dump(pk_data, f)

        sk_data = addition_info(sk)
        sk_data['is_public'] = False
        sk_path = self.my_keys_dir / ('.' + self.title_box.get() + '.key')
        with sk_path.open('w') as f:
            json.dump(sk_data, f)

if __name__ =='__main__':
    root = tk.Tk()
    Main_Window(root)
    root.update()
    root.minsize(350, 400)
    root.mainloop()
