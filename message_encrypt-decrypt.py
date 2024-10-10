# import tkinter module
from tkinter import *

# import other necessary modules
import random
import time
import datetime

# creating root object
root = Tk()

# defining size of window
root.geometry("1200x6000")

# setting up the title of window
root.title("Message Encryption and Decryption")

# Professional and light color scheme
bg_color = "#f0f0f0"  # Light gray background
frame_color = "#ffffff"  # White background for frames
btn_color = "#dcdcdc"  # Light button color
text_color = "#333333"  # Dark text color
accent_color = "#5A9"  # Accent color for headers and highlights

# Frames
Tops = Frame(root, width=1600, relief=SUNKEN, bg=frame_color)
Tops.pack(side=TOP)

f1 = Frame(root, width=800, height=700, relief=SUNKEN, bg=frame_color)
f1.pack(side=LEFT)

# ==============================================
#                  TIME
# ==============================================
localtime = time.asctime(time.localtime(time.time()))

lblInfo = Label(Tops, font=('Helvetica', 40, 'bold'),
                text="SECRET MESSAGING \nVigenère Cipher",
                fg=accent_color, bg=frame_color, bd=10, anchor='w')
lblInfo.grid(row=0, column=0)

lblInfo = Label(Tops, font=('Arial', 16, 'bold'),
                text=localtime, fg=text_color, bg=frame_color, bd=10, anchor='w')
lblInfo.grid(row=1, column=0)

# StringVar initialization
rand = StringVar()
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()


# exit function
def qExit():
    root.destroy()


# Function to reset the window
def Reset():
    rand.set("")
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")


# reference
lblReference = Label(f1, font=('Arial', 14, 'bold'),
                     text="Name:", bd=16, anchor="w", fg=text_color, bg=frame_color)
lblReference.grid(row=0, column=0)

txtReference = Entry(f1, font=('Arial', 14, 'bold'),
                     textvariable=rand, bd=10, insertwidth=4,
                     bg=bg_color, justify='right', fg=text_color)
txtReference.grid(row=0, column=1)

# labels
lblMsg = Label(f1, font=('Arial', 14, 'bold'),
               text="MESSAGE", bd=16, anchor="w", fg=text_color, bg=frame_color)
lblMsg.grid(row=1, column=0)

txtMsg = Entry(f1, font=('Arial', 14, 'bold'),
               textvariable=Msg, bd=10, insertwidth=4,
               bg=bg_color, justify='right', fg=text_color)
txtMsg.grid(row=1, column=1)

lblkey = Label(f1, font=('Arial', 14, 'bold'),
               text="KEY", bd=16, anchor="w", fg=text_color, bg=frame_color)
lblkey.grid(row=2, column=0)

txtkey = Entry(f1, font=('Arial', 14, 'bold'),
               textvariable=key, bd=10, insertwidth=4,
               bg=bg_color, justify='right', fg=text_color)
txtkey.grid(row=2, column=1)

lblmode = Label(f1, font=('Arial', 14, 'bold'),
                text="MODE (e for encrypt, d for decrypt)", bd=16, anchor="w",
                fg=text_color, bg=frame_color)
lblmode.grid(row=3, column=0)

txtmode = Entry(f1, font=('Arial', 14, 'bold'),
                textvariable=mode, bd=10, insertwidth=4,
                bg=bg_color, justify='right', fg=text_color)
txtmode.grid(row=3, column=1)

lblService = Label(f1, font=('Arial', 14, 'bold'),
                   text="The Result:", bd=16, anchor="w", fg=text_color, bg=frame_color)
lblService.grid(row=2, column=2)

txtService = Entry(f1, font=('Arial', 14, 'bold'),
                   textvariable=Result, bd=10, insertwidth=4,
                   bg=bg_color, justify='right', fg=text_color)
txtService.grid(row=2, column=3)

# Vigenère cipher
import base64


# Function to encode
def encode(key, clear):
    enc = []

    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) +
                     ord(key_c)) % 256)

        enc.append(enc_c)

    return base64.urlsafe_b64encode("".join(enc).encode()).decode()


# Function to decode
def decode(key, enc):
    dec = []

    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) -
                     ord(key_c)) % 256)

        dec.append(dec_c)
    return "".join(dec)


def Ref():
    clear = Msg.get()
    k = key.get()
    m = mode.get()

    if m == 'e':
        Result.set(encode(k, clear))
    else:
        Result.set(decode(k, clear))


# Show message button
btnTotal = Button(f1, padx=16, pady=8, bd=16, fg=text_color,
                  font=('Arial', 14, 'bold'), width=10,
                  text="Show Message", bg=btn_color,
                  command=Ref).grid(row=7, column=1)

# Reset button
btnReset = Button(f1, padx=16, pady=8, bd=16,
                  fg=text_color, font=('Arial', 14, 'bold'),
                  width=10, text="Reset", bg=btn_color,
                  command=Reset).grid(row=7, column=2)

# Exit button
btnExit = Button(f1, padx=16, pady=8, bd=16,
                 fg=text_color, font=('Arial', 14, 'bold'),
                 width=10, text="Exit", bg="#ff6b6b",  # Light red for exit button
                 command=qExit).grid(row=7, column=3)

# keeps window alive
root.config(bg=bg_color)
root.mainloop()
