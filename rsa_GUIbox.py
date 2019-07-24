# -*- coding: utf-8 -*-
"""
Created on Thu Jul  4 08:20:26 2019

@author: R20979
"""

import rsa_tools
import tkinter as tk
from tkinter import ttk
import re

class Init_key(ttk.Frame):
    def __init__(self, master=None):
        super().__init__(master)
        self.create_widgets()
        self.my_key = None

    def create_widgets(self):
        ttk.Label(text='key').grid(row=0, column=0, sticky='w')
        self.editbox = ttk.Entry()
        self.editbox.grid(row=1, column=0, columnspan=2, sticky='w')
        ttk.Button(text='登録', command=self.button_clicked).grid()
        self.grid(row=2, column=0, sticky='w')

    def button_clicked(self):
        p = r'\(\d+[,|\n| ]+\d+\)'
        key = self.editbox.get()
        m = re.match(p, key)
        if m and len(key)==m.end():
            self.my_key = self.str2tuple(key)
            self.grid_forget()
            self.destroy()
        else:
            self.editbox.delete(0, tk.END)
            print("not match")

    def str2tuple(self, string_key):
        str_list = re.split('[,|\n| ]+', string_key.strip('()[]'))
        return tuple(map(int, str_list))

if __name__ =='__main__':
    root = tk.Tk()
    root.title('あああ')
    Init_key(root)
    root.mainloop()
