import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import string
import random

class PasswordGenerator:
    def __init__(self, master):
        self.master = master
        self.master.title("Password Generator")
        self.master.geometry("400x250")

        # GUI elements
        self.label_length = tk.Label(master, text="Password Length:")
        self.label_length.pack()

        self.length_var = tk.StringVar()
        self.entry_length = tk.Entry(master, textvariable=self.length_var)
        self.entry_length.pack()

        self.label_options = tk.Label(master, text="Password Options:")
        self.label_options.pack()

        self.lower_var = tk.IntVar()
        self.check_lower = tk.Checkbutton(master, text="Lowercase Letters", variable=self.lower_var)
        self.check_lower.pack()

        self.upper_var = tk.IntVar()
        self.check_upper = tk.Checkbutton(master, text="Uppercase Letters", variable=self.upper_var)
        self.check_upper.pack()

        self.digit_var = tk.IntVar()
        self.check_digit = tk.Checkbutton(master, text="Digits", variable=self.digit_var)
        self.check_digit.pack()

        self.special_var = tk.IntVar()
        self.check_special = tk.Checkbutton(master, text="Special Characters", variable=self.special_var)
        self.check_special.pack()

        self.generate_button = tk.Button(master, text="Generate Password", command=self.generate_password)
        self.generate_button.pack()

        self.password_var = tk.StringVar()
        self.entry_password = tk.Entry(master, textvariable=self.password_var, state='readonly')
        self.entry_password.pack()

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            if length <= 0:
                raise ValueError("Password length must be greater than 0.")

            options = {
                'lowercase': string.ascii_lowercase if self.lower_var.get() else '',
                'uppercase': string.ascii_uppercase if self.upper_var.get() else '',
                'digits': string.digits if self.digit_var.get() else '',
                'special': string.punctuation if self.special_var.get() else ''
            }

            characters = ''.join(options.values())
            if not characters:
                raise ValueError("Select at least one option for password generation.")

            password = ''.join(random.choice(characters) for _ in range(length))
            self.password_var.set(password)
        except ValueError as e:
            messagebox.showerror("Password Generator", str(e))

def main():
    root = tk.Tk()
    app = PasswordGenerator(root)
    root.mainloop()

if __name__ == "__main__":
    main()
