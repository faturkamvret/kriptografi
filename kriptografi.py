import tkinter as tk
from tkinter import filedialog

class CipherProgram:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Program")

        self.file_label = tk.Label(root, text="Select a file or input a message:")
        self.file_label.pack()
       
        self.file_frame = tk.Frame(root)
        self.file_frame.pack()

        self.file_entry = tk.Text(self.file_frame, width=50, height=10)
        self.file_entry.grid(row=0, column=0, columnspan=2)
        self.file_entry.config(state='disabled') 

        self.upload_button = tk.Button(self.file_frame, text="Upload File", command=self.upload_file)
        self.upload_button.grid(row=1, column=0)

        self.clear_button = tk.Button(self.file_frame, text="Clear Text", command=self.clear_text)
        self.clear_button.grid(row=1, column=1)

        self.message_label = tk.Label(root, text="Input a message:")
        self.message_label.pack()

        self.message_entry = tk.Entry(root, width=50)
        self.message_entry.pack()

        self.key_label = tk.Label(root, text="Input a key (min. 12 characters):")
        self.key_label.pack()

        self.key_entry = tk.Entry(root, width=50)
        self.key_entry.pack()

        self.cipher_label = tk.Label(root, text="Choose a cipher:")
        self.cipher_label.pack()

        self.cipher_var = tk.StringVar()
        self.cipher_var.set("Vigenere")

        self.vigenere_radio = tk.Radiobutton(root, text="Vigenere", variable=self.cipher_var, value="Vigenere")
        self.vigenere_radio.pack()

        self.playfair_radio = tk.Radiobutton(root, text="Playfair", variable=self.cipher_var, value="Playfair")
        self.playfair_radio.pack()

        self.hill_radio = tk.Radiobutton(root, text="Hill", variable=self.cipher_var, value="Hill")
        self.hill_radio.pack()

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt)
        self.encrypt_button.pack()

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt)
        self.decrypt_button.pack()

        self.result_label = tk.Label(root, text="Result:")
        self.result_label.pack()

        self.result_entry = tk.Entry(root, width=50)
        self.result_entry.pack()

    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r") as file:
                self.file_entry.config(state='normal')  
                self.file_entry.delete(1.0, tk.END)
                self.file_entry.insert(tk.END, file.read())
                self.file_entry.config(state='disabled')  

    def clear_text(self):
        """Clear all text inputs and results."""
        self.file_entry.config(state='normal')
        self.file_entry.delete(1.0, tk.END)  
        self.file_entry.config(state='disabled')
        self.message_entry.delete(0, tk.END)  
        self.key_entry.delete(0, tk.END) 
        self.result_entry.delete(0, tk.END)  

    def encrypt(self):
        cipher = self.cipher_var.get()
        key = self.key_entry.get()
        message = self.file_entry.get(1.0, tk.END).strip() or self.message_entry.get()

        if len(key) < 12:
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, "Key must be at least 12 characters long.")
            return

        result = ""

        if cipher == "Vigenere":
            result = self.vigenere_encrypt(message, key)
        elif cipher == "Playfair":
            result = self.playfair_encrypt(message, key)
        elif cipher == "Hill":
            result = self.hill_encrypt(message, key)

        self.result_entry.delete(0, tk.END)
        self.result_entry.insert(0, result)

    def decrypt(self):
        cipher = self.cipher_var.get()
        key = self.key_entry.get()
        message = self.file_entry.get(1.0, tk.END).strip() or self.message_entry.get()

        if len(key) < 12:
            self.result_entry.delete(0, tk.END)
            self.result_entry.insert(0, "Key must be at least 12 characters long.")
            return

        result = ""

        if cipher == "Vigenere":
            result = self.vigenere_decrypt(message, key)
        elif cipher == "Playfair":
            result = self.playfair_decrypt(message, key)
        elif cipher == "Hill":
            result = self.hill_decrypt(message, key)

        self.result_entry.delete(0, tk.END)
        self.result_entry.insert(0, result)

    # Metode Viginere Cipher
    def vigenere_encrypt(self, text, key):
        text = text.upper().replace(" ", "")
        key = key.upper()
        result = []
        for i in range(len(text)):
            char = (ord(text[i]) - ord('A') + ord(key[i % len(key)]) - ord('A')) % 26
            result.append(chr(char + ord('A')))
        return ''.join(result)

    def vigenere_decrypt(self, text, key):
        text = text.upper().replace(" ", "")
        key = key.upper()
        result = []
        for i in range(len(text)):
            char = (ord(text[i]) - ord('A') - (ord(key[i % len(key)]) - ord('A'))) % 26
            result.append(chr(char + ord('A')))
        return ''.join(result)

    # Metode Playfair Cipher
    def prepare_input(self, text):
        text = text.upper().replace(" ", "")
        result = []
        for char in text:
            if char == 'J':
                result.append('I')
            else:
                result.append(char)
        return ''.join(result)

    def generate_table(self, key):
        key = key.upper().replace(" ", "")
        alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        table = []
        for char in key:
            if char not in table:
                table.append(char)
        for char in alphabet:
            if char not in table:
                table.append(char)
        return [table[i:i + 5] for i in range(0, 25, 5)]

    # hanya memproses jumlah char genap , jika ganjil maka akan kita ganti ke X
    def playfair_encrypt(self, text, key):
        text = self.prepare_input(text)
        table = self.generate_table(key)
        if len(text) % 2 != 0:
            text += 'X'  
        result = []
        for i in range(0, len(text), 2):
            char1 = text[i]
            char2 = text[i + 1]
            row1, col1 = [( index, row.index(char1)) for index, row in enumerate(table) if char1 in row][0]
            row2, col2 = [(index, row.index(char2)) for index, row in enumerate(table) if char2 in row][0]
            if row1 == row2:
                result.append(table[row1][(col1 + 1) % 5])
                result.append(table[row2][(col2 + 1) % 5])
            elif col1 == col2:
                result.append(table[(row1 + 1) % 5][col1])
                result.append(table[(row2 + 1) % 5][col2])
            else:
                result.append(table[row1][col2])
                result.append(table[row2][col1])
        return ''.join(result)

    def playfair_decrypt(self, text, key):
        text = self.prepare_input(text)
        if len(text) % 2 != 0:
            text += 'X' 
        table = self.generate_table(key)
        result = []
        for i in range(0, len(text), 2):
            char1 = text[i]
            char2 = text[i + 1]
            row1, col1 = [(index, row.index(char1)) for index, row in enumerate(table) if char1 in row][0]
            row2, col2 = [(index, row.index(char2)) for index, row in enumerate(table) if char2 in row][0]
            if row1 == row2: 
                result.append(table[row1][(col1 - 1) % 5])
                result.append(table[row2][(col2 - 1) % 5])
            elif col1 == col2: 
                result.append(table[(row1 - 1) % 5][col1])
                result.append(table[(row2 - 1) % 5][col2])
            else:  
                result.append(table[row1][col2])
                result.append(table[row2][col1])
        return ''.join(result)

    # Metode Hill Cypher
    def is_key_invertible(self, key):
        key = [ord(char) - 65 for char in key]
        if len(key) != 4:
            return False  # Kunci Harus berjumlah 4 karena matriks
        key_matrix = [key[0:2], key[2:4]]
        det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) % 26
        return det != 0 and self.gcd(det, 26) == 1

    def gcd(self, a, b):
        while b:
            a, b = b, a % b
        return a

    def hill_encrypt(self, text, key):
        if not self.is_key_invertible(key):
            return "Key is not invertible."
        text = text.upper().replace(" ", "")
        if len(text) % 2 != 0:
            text += 'X'  # 
        key = [ord(char) - 65 for char in key]
        key_matrix = [key[0:2], key[2:4]]
        result = []
        for i in range(0, len(text), 2):
            char1 = ord(text[i]) - 65
            char2 = ord(text[i + 1]) - 65
            encrypted_char1 = (key_matrix[0][0] * char1 + key_matrix[0][1] * char2) % 26
            encrypted_char2 = (key_matrix[1][0] * char1 + key_matrix[1][1] * char2) % 26
            result.append(chr(encrypted_char1 + 65))
            result.append(chr(encrypted_char2 + 65))
        return ''.join(result)

    def hill_decrypt(self, text, key):
        if not self.is_key_invertible(key):
            return "Key is not invertible."
        text = text.upper().replace(" ", "")
        key = [ord(char) - 65 for char in key]
        key_matrix = [key[0:2], key[2:4]]
        det = (key_matrix[0][0] * key_matrix[1][1] - key_matrix[0][1] * key_matrix[1][0]) % 26
        inv_det = pow(det, -1, 26)  # Find modular inverse
        inv_key_matrix = [
            [(key_matrix[1][1] * inv_det) % 26, (-key_matrix[0][1] * inv_det) % 26],
            [(-key_matrix[1][0] * inv_det) % 26, (key_matrix[0][0] * inv_det) % 26]
        ]
        result = []
        for i in range(0, len(text), 2):
            char1 = ord(text[i]) - 65
            char2 = ord(text[i + 1]) - 65
            decrypted_char1 = (inv_key_matrix[0][0] * char1 + inv_key_matrix[0][1] * char2) % 26
            decrypted_char2 = (inv_key_matrix[1][0] * char1 + inv_key_matrix[1][1] * char2) % 26
            result.append(chr(decrypted_char1 + 65))
            result.append(chr(decrypted_char2 + 65))
        return ''.join(result)

root = tk.Tk()
cipher_program = CipherProgram(root)
root.mainloop()