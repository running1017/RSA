# -*- coding: utf-8 -*-
"""
Created on Thu Jul  4 08:20:26 2019

@author: R20979
"""

import rsa_tools_obj
import tkinter as tk
from tkinter import ttk

class Main_Window(ttk.Notebook):
    def __init__(self, master=None):
        super().__init__(master)

    def create_widgets(self):
        

class Key_Tab(tk.Frame):
    def __init__(self, master=None):
        super().__init__(master)


if __name__ =='__main__':
    root = tk.Tk()
    root.title('main job')
    Main_Window(root)
    root.mainloop()
