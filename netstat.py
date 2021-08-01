#!/usr/bin/python
import subprocess, sys
import codecs
import locale
import time
import threading
import tkinter as tk

## local host ip for filtering
Host = "192.168.1.23"
## command to run - tcp only ##
cmd = "netstat -natu|grep '192.168.1.23'"
alist = []
allowedlist = ["192.168.1.1:67"]

def popupmsg(msg, title):
    root = tk.Tk()
    root.title(title)
    label = tk.Label(root, text=msg)
    label.pack(side="top", fill="x", pady=10)
    B1 = tk.Button(root, text="Okay", command = root.destroy)
    B1.pack()
    root.mainloop()

popupmsg("Alert","emergency")

def getstdout(p, asy):
    if asy:
        alist.clear()
    mylist = []
    while True:
        data = p.stdout.readline()
        if data == b'':
            if p.poll() is not None:
                break
        else:
            if asy:
                alist.append(data.decode(codecs.lookup(locale.getpreferredencoding()).name))
            else:
                mylist.append(data.decode(codecs.lookup(locale.getpreferredencoding()).name))
    return mylist
## run it ##
while True:
    ps = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, shell=True)
    resultlist = getstdout(ps, False)
    if len(resultlist) >=1:
        for i in resultlist:
            data = i.split("      ") 
            if data[3].strip() not in allowedlist:
                print("Foreign Host" + data[3] + data[4])
                popupmsg("Foreign Host"+data[3]+data[4],"INTRUSION")
                time.sleep(10)

