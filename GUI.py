from tkinter import *
import os


def donothing():
   filewin = Toplevel(tk)
   filewin.minsize(500, 300)
   button = Button(filewin, text="Do nothing button")
   button.pack()

tk = Tk()
tk.minsize(800, 600)
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
menubar.add_cascade(label="File", menu=filemenu)

# Edit
editmenu = Menu(menubar, tearoff=0)
editmenu.add_command(label="Undo", command=donothing)
editmenu.add_separator()
editmenu.add_command(label="Cut", command=donothing)
editmenu.add_command(label="Copy", command=donothing)
editmenu.add_command(label="Paste", command=donothing)
editmenu.add_command(label="Delete", command=donothing)
editmenu.add_command(label="Select All", command=donothing)
menubar.add_cascade(label="Edit", menu=editmenu)

#Help
helpmenu = Menu(menubar, tearoff=0)
helpmenu.add_command(label="Help Index", command=donothing)
helpmenu.add_command(label="About...", command=donothing)
menubar.add_cascade(label="Help", menu=helpmenu)


Label(tk, text = "Target URL").grid(row = 0, sticky = W)
url_field = Entry(tk)

url_field.grid(row = 0, column = 1)

def get_input():
    a = url_field.get()
    return a

def call_sqlmap():
    os.chdir("sqlmap-dev")
    os.system(f"python sqlmap.py -u {url_field.get()}")


Button(tk, text = "submit",
           command = call_sqlmap).grid(row = 5, sticky = W)

# os.system(f'python test.py -{getInput()}')

tk.config(menu=menubar)
tk.mainloop()