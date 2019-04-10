"""TODO"""
from tkinter import *
import os
from application import start_configer


def execute_configer():
    mode = None
    url = url_field.get()
    if r_var.get() == '--enterprise':
        mode = 'enterprise'
    elif r_var.get() == '--local':
        mode = 'local'
    start_configer(mode=mode, url=url)
    sys.exit(1)

def donothing():
    filewin = Toplevel(tk)
    filewin.minsize(500, 300)
    button = Button(filewin, text="Do nothing button")
    button.pack()

tk = Tk()
tk.title('OWASPscan')
tk.minsize(600, 400)

menubar = Menu(tk)

# File
filemenu = Menu(menubar, tearoff=0)
filemenu.add_command(label="New", command=donothing)
filemenu.add_command(label="Open", command=donothing)
filemenu.add_command(label="Save", command=donothing)
filemenu.add_command(label="Save as...", command=donothing)
filemenu.add_command(label="Close", command=donothing)
filemenu.add_separator()
filemenu.add_command(label="Exit", command=tk.quit)
menubar.add_cascade(label="OWASPscan", menu=filemenu)

# Edit
editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Undo", command=donothing)
editmenu.add_separator()
editmenu.add_command(label="Cut", command=donothing)
editmenu.add_command(label="Copy", command=donothing)
editmenu.add_command(label="Paste", command=donothing)
editmenu.add_command(label="Delete", command=donothing)
editmenu.add_command(label="Select All", command=donothing)
menubar.add_cascade(label="Settings", menu=editmenu)

#Help
helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="Help Index", command=donothing)
helpmenu.add_command(label="About...", command=donothing)
menubar.add_cascade(label="Help", menu=helpmenu)

Label(tk, text = "Target URL").grid(row = 0, sticky = W)
url_field = Entry(tk)
url_field.grid(row = 0, column = 1, padx = 20)

r_var = StringVar()
r_var.set('--enterprise')

Radiobutton(tk, text='localhost', padx = 20, variable=r_var, value='--local').grid(row = 1, column = 1)
Radiobutton(tk, text='enterprise', padx = 20, variable=r_var, value='--enterprise').grid(row = 2, column = 1)

Button(tk, text = "Begin scan", command = execute_configer).grid(row = 5, sticky = W)

copyright = "OWASPscan 2019"
label2 = Label(text=copyright, justify=LEFT, fg="grey")
label2.place(relx=0, rely=0.96)

tk.config(menu=menubar)
tk.mainloop()
