# -*- coding: utf-8 -*-
"""
Created on Thu Jul  4 08:20:26 2019

@author: R20979
"""

import rsa_tools_obj
import tkinter as tk
from tkinter import ttk

# ウィンドウ全体の処理
class Main_Window(ttk.Notebook):
    def __init__(self, master=None):
        super().__init__(master)
        self.master.title('main job')

        # メインタブの作成
        main_tab = tk.Frame(self.master)
        self.add(main_tab, text="crypt")
        Main_Tab(master=main_tab)

        # キータブの作成
        key_tab = tk.Frame(self.master)
        self.add(key_tab, text="key config")
        Key_Tab(master=key_tab)

        self.pack()


# メインタブの処理
class Main_Tab(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_widgets()

    # ウィジェットの作成
    def create_widgets(self):
        
        input_box = tk.Text(font=("MS Pゴシック"))


# キーの作成・登録・切り替えをするタブの処理
class Key_Tab(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_widgets()

    def create_widgets(self):
        pass


if __name__ =='__main__':
    root = tk.Tk()
    Main_Window(root)
    root.mainloop()
