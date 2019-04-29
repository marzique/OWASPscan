"""GUI app wrapper"""
from tkinter import *
from tkinter import messagebox, filedialog
import os
from application import start_configer, start_loginer
import time


settings = {"local": False,
            "page_limit": None,
            "vocabulary": False,
            }

def execute():
    start = time.time()

    url = url_field.get()
    if not url:
        provide_url()
        return

    try:
        lim = int(limit.get())
        settings["page_limit"] = lim
    except:
        pass

    if r_var.get() == "--enterprise":
        settings["local"] = False
    elif r_var.get() == "--local":
        settings["local"] = True
    c = start_configer(settings, url=url)
    l = start_loginer(c)

    time_minutes = str((time.time() - start) / 60)[:4]
    print(f"OWASPscan took {time_minutes} minutes")
    sys.exit(1)

def donothing():
    filewin = Toplevel(tk)
    filewin.minsize(500, 300)
    button = Button(filewin, text="Do nothing button")
    button.pack()

def provide_url():
    messagebox.showinfo("Error", "Please provide target URL!")

def toggle_pagelimit():
    if not page_limit.get():
        limit.grid_remove()
        limitlabel.grid_remove()
    else:
        limit.grid(row = 4, column = 1, sticky=E)
        limitlabel.grid(row = 4, sticky=E)


def choose_folder():
    dirname = filedialog.askdirectory(parent=tk, initialdir="/", title='Please select a website root directory')
    return dirname

tk = Tk()
tk.title("OWASPscan")
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

# URL
Label(tk, text = "Target URL:", width=15).grid(row = 0, sticky=E)
url_field = Entry(tk)
url_field.grid(row = 0, column = 1, sticky = W)

r_var = StringVar()
r_var.set("--enterprise")

# Select project's folder
Button(tk, text = "Website root folder", command = choose_folder, bg="blue", fg="white").grid(row = 1, column = 1, sticky = W)

# Server type
Label(tk, text = "Server:").grid(row = 2, column = 0, sticky=E)
Radiobutton(tk, text="localhost", variable=r_var, value="--local").grid(row = 2, column = 1, sticky = W)
Radiobutton(tk, text="enterprise", variable=r_var, value="--enterprise").grid(row = 3, column = 1, sticky = W)


# Page search limit
Label(tk, text = "limit pages?").grid(row = 4, column = 0, sticky=E)
page_limit = IntVar()
Checkbutton(tk, variable=page_limit, command=toggle_pagelimit).grid(row=5, column = 1, sticky=W)
limitlabel = Label(tk, text = "Page search limit:")
limit = Entry(tk)

# Search button
Button(tk, text = "Begin scan", command = execute, bg="green", fg="white").grid(row = 6, column = 1, sticky = W)

label2 = Label(text="Tarnavskyi Denys, 2019", justify=LEFT, fg="grey")
label2.place(relx=0, rely=0.95)

tk.config(menu=menubar)
tk.mainloop()
