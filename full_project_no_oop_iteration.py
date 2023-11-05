import tkinter as tk
from tkinter import filedialog
import os
from tkinter import messagebox

def caesar_cipher(text, shift, russian=False, ascii_range=False):
    result = ''

    if russian:
        start_char, end_char = 'а', 'я'
        start_upper, end_upper = 'А', 'Я'
    else:
        start_char, end_char = 'a', 'z'
        start_upper, end_upper = 'A', 'Z'

    for char in text:
        if char == 'ё' and russian:
            start_char, end_char = 'а', 'я'  # Update range for 'ё'
            start_upper, end_upper = 'А', 'Я'

        if start_char <= char <= end_char:
            start = ord(start_char)
        elif start_upper <= char <= end_upper:
            start = ord(start_upper)
        else:
            result += char
            continue

        shifted_char = ord(char) - start + shift
        alphabet_size = ord(end_char) - ord(start_char) + 1
        shifted_char %= alphabet_size

        result += chr(start + shifted_char)

    return result


def vigenere_cipher(text, key, russian=False, ascii_range=False):
    result = ''
    key_length = len(key)
    counter = 0  # Initialize a counter for the key

    if russian:
        start_char, end_char = 'а', 'я'
        start_upper, end_upper = 'А', 'Я'
    else:
        start_char, end_char = 'a', 'z'
        start_upper, end_upper = 'A', 'Z'

    for char in text:
        if char == 'ё' and russian:
            start_char, end_char = 'а', 'я'  # Update range for 'ё'
            start_upper, end_upper = 'А', 'Я'

        if start_char <= char <= end_char:
            start = ord(start_char)
        elif start_upper <= char <= end_upper:
            start = ord(start_upper)
        else:
            result += char
            continue

        shift = ord(key[counter]) - ord(start_char)

        shifted_char = ord(char) - start + shift
        alphabet_size = ord(end_char) - ord(start_char) + 1
        shifted_char %= alphabet_size
        result += chr(start + shifted_char)

        counter = (counter + 1) % key_length

    return result


def vigenere_decipher(ciphertext, key, russian=False, ascii_range=False):
    result = ''
    key_length = len(key)
    counter = 0  # Initialize a counter for the key

    if russian:
        start_char, end_char = 'а', 'я'
        start_upper, end_upper = 'А', 'Я'
    else:
        start_char, end_char = 'a', 'z'
        start_upper, end_upper = 'A', 'Z'

    for char in ciphertext:
        if char == 'ё' and russian:
            start_char, end_char = 'а', 'я'  # Update range for 'ё'
            start_upper, end_upper = 'А', 'Я'

        if start_char <= char <= end_char:
            start = ord(start_char)
        elif start_upper <= char <= end_upper:
            start = ord(start_upper)
        else:
            result += char
            continue

        shift = ord(key[counter]) - ord(start_char)

        shifted_char = ord(char) - start - shift
        alphabet_size = ord(end_char) - ord(start_char) + 1
        shifted_char = (shifted_char + alphabet_size) % alphabet_size

        result += chr(start + shifted_char)

        counter = (counter + 1) % key_length

    return result

def vernam_cipher(text, key):
    result = ''
    if len(key) < len(text):
        raise ValueError("Ключ должен быть не короче текста.")
        messagebox.showerror("Ошибка", str(e))

    for char, key_char in zip(text, key):
        encrypted_char = ord(char) ^ ord(key_char)
        result += chr(encrypted_char)

    return result

def encrypt_caesar(input_file, output_file, shift, russian, ascii_range):
    with open(input_file, 'r', encoding='utf-8') as file:
        plaintext = file.read()
        encrypted_text = caesar_cipher(plaintext, shift, russian, ascii_range)
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(encrypted_text)

def decrypt_caesar(input_file, output_file, shift, russian, ascii_range):
    with open(input_file, 'r', encoding='utf-8') as file:
        encrypted_text = file.read()
        decrypted_text = caesar_cipher(encrypted_text, -shift, russian, ascii_range)
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(decrypted_text)

def encrypt_vigenere(input_file, output_file, key, russian, ascii_range):
    with open(input_file, 'r', encoding='utf-8') as file:
        plaintext = file.read()
        encrypted_text = vigenere_cipher(plaintext, key, russian, ascii_range)
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(encrypted_text)

def decrypt_vigenere(input_file, output_file, key, russian, ascii_range):
    with open(input_file, 'r', encoding='utf-8') as file:
        encrypted_text = file.read()
        decrypted_text = vigenere_decipher(encrypted_text, key, russian, ascii_range)
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(decrypted_text)

def encrypt_vernam(input_file, output_file, key):
    with open(input_file, 'r', encoding='utf-8') as file:
        plaintext = file.read()
        encrypted_text = vernam_cipher(plaintext, key)
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(encrypted_text)

def decrypt_vernam(input_file, output_file, key):
    with open(input_file, 'r', encoding='utf-8') as file:
        encrypted_text = file.read()
        decrypted_text = vernam_cipher(encrypted_text, key)
    with open(output_file, 'w', encoding='utf-8') as file:
        file.write(decrypted_text)
def calculate_letter_frequencies(text):
    frequencies = {}
    for char in text:
        if char.isalpha():
            char = char.lower()
            if char in frequencies:
                frequencies[char] += 1
            else:
                frequencies[char] = 1
    total = sum(frequencies.values())
    frequencies = {char: count / total for char, count in frequencies.items()}
    return frequencies

def caesar_frequency_analysis(ciphertext, language_frequencies):
    if language_frequencies == russian_frequencies:
        shift_range = range(1, 33)  # Shift range for the Russian alphabet
    else:
        shift_range = range(1, 27)  # Shift range for English alphabet

    best_shift = None
    best_score = float('-inf')

    for shift in shift_range:
        decrypted_text = ''
        for char in ciphertext:
            if char.isalpha():
                if language_frequencies == russian_frequencies:
                    shifted_char = chr(((ord(char.lower()) - ord('а') - shift) % 32) + ord('а'))
                    decrypted_text += shifted_char if char.islower() else shifted_char.upper()
                else:
                    shifted_char = chr(((ord(char.lower()) - ord('a') - shift) % 26) + ord('a'))
                    decrypted_text += shifted_char if char.islower() else shifted_char.upper()
            else:
                decrypted_text += char

        frequencies = calculate_letter_frequencies(decrypted_text)
        score = sum(language_frequencies.get(char, 0) * frequencies[char] for char in frequencies)
        if score > best_score:
            best_score = score
            best_shift = shift

    return best_shift

russian_frequencies = {
    'а': 0.0801, 'б': 0.0159, 'в': 0.0454, 'г': 0.0170, 'д': 0.0298,
    'е': 0.0845, 'ё': 0.001, 'ж': 0.0094, 'з': 0.0165, 'и': 0.0735, 'й': 0.0121,
    'к': 0.0349, 'л': 0.044, 'м': 0.0321, 'н': 0.067, 'о': 0.1097,
    'п': 0.0281, 'р': 0.0473, 'с': 0.0547, 'т': 0.0626, 'у': 0.0262,
    'ф': 0.0027, 'х': 0.0097, 'ц': 0.0064, 'ч': 0.0144, 'ш': 0.0073,
    'щ': 0.0043, 'ъ': 0.0004, 'ы': 0.019, 'ь': 0.0174, 'э': 0.0032,
    'ю': 0.0067, 'я': 0.0201
}

english_frequencies = {
    'a': 0.0817, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.127,
    'f': 0.0223, 'g': 0.0202, 'h': 0.0609, 'i': 0.0697, 'j': 0.0015,
    'k': 0.0077, 'l': 0.0403, 'm': 0.0241, 'n': 0.0675, 'o': 0.0751,
    'p': 0.0193, 'q': 0.00095, 'r': 0.0599, 's': 0.0633, 't': 0.0906,
    'u': 0.0276, 'v': 0.0098, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
    'z': 0.00074
}

def open_file():
    file_path = filedialog.askopenfilename()
    input_entry.delete(0, tk.END)
    input_entry.insert(0, file_path)

def save_file():
    file_path = filedialog.asksaveasfilename()
    output_entry.delete(0, tk.END)
    output_entry.insert(0, file_path)

def go_back():
    if selected_cipher:
        frame_cipher_options.pack_forget()
    frame_choose_cipher.pack()

def select_cipher(cipher):
    frame_choose_cipher.pack_forget()
    frame_cipher_options.pack()

    global selected_cipher
    selected_cipher = cipher

def toggle_russian():
    if russian_var.get():
        ascii_range_var.set(False)

def toggle_ascii_range():
    if ascii_range_var.get():
        russian_var.set(False)

def toggle_encrypt():
    if encrypt_var.get():
        decrypt_var.set(False)

def toggle_decrypt():
    if decrypt_var.get():
        encrypt_var.set(False)
def go_back_to_menu():
    frame_frequency_analysis.pack_forget()
    frame_choose_cipher.pack()
def show_frequency_analysis_scene():
    frame_choose_cipher.pack_forget()
    frame_frequency_analysis.pack()


def process():
    cipher_type = cipher_type_var.get()

    if cipher_type == "caesar":
        process_caesar()
    elif cipher_type == "vigenere":
        process_vigenere()
    elif cipher_type == "vernam":
        process_vernam()


def process_caesar():
    input_file = input_entry.get()
    output_file = output_entry.get()
    shift = int(shift_entry.get())
    russian = russian_var.get()
    ascii_range = ascii_range_var.get()

    if encrypt_var.get():
        encrypt_caesar(input_file, output_file, shift, russian, ascii_range)
        res_label.config(text="Caesar Encryption done! File saved as " + output_file)
    else:
        decrypt_caesar(input_file, output_file, shift, russian, ascii_range)
        res_label.config(text="Caesar Decryption done! File saved as " + output_file)

def process_vigenere():
    input_file = input_entry.get()
    output_file = output_entry.get()
    key = key_entry.get()
    russian = russian_var.get()
    ascii_range = ascii_range_var.get()

    if encrypt_var.get():
        encrypt_vigenere(input_file, output_file, key, russian, ascii_range)
        res_label.config(text="Vigenere Encryption done! File saved as " + output_file)
    else:
        decrypt_vigenere(input_file, output_file, key, russian, ascii_range)
        res_label.config(text="Vigenere Decryption done! File saved as " + output_file)

def process_vernam():
    input_file = input_entry.get()
    output_file = output_entry.get()
    key = key_entry.get()

    if encrypt_var.get():
        encrypt_vernam(input_file, output_file, key)
        res_label.config(text="Vernam Encryption done! File saved as " + output_file)
    else:
        decrypt_vernam(input_file, output_file, key)
        res_label.config(text="Vernam Decryption done! File saved as " + output_file)


def analyze_button_clicked():
    ciphertext = input_text.get("1.0", "end-1c")
    language = selected_language.get()
    if language == "Russian":
        language_frequencies = russian_frequencies
    else:
        language_frequencies = english_frequencies
    best_shift = caesar_frequency_analysis(ciphertext, language_frequencies)
    result_label.config(text=f"Best Shift: {best_shift}")
def set_cipher_type(cipher_type):
    cipher_type_var.set(cipher_type)
app = tk.Tk()
app.title("Caesar, Vigenere, and Vernam Cipher")
app.configure(bg='turquoise')

frame_choose_cipher = tk.Frame(app, bg='turquoise')
frame_choose_cipher.pack(pady=10)

frame_cipher_options = tk.Frame(app, bg='turquoise')
frame_cipher_options.pack(pady=10)
frame_cipher_options.pack_forget()

frame_frequency_analysis = tk.Frame(app, bg='turquoise')
frame_frequency_analysis.pack(pady=10)
frame_frequency_analysis.pack_forget()

caesar_button = tk.Button(frame_choose_cipher, text="Caesar Cipher", command=lambda: [select_cipher("caesar"), set_cipher_type("caesar")], width=20)
vigenere_button = tk.Button(frame_choose_cipher, text="Vigenere Cipher", command=lambda: [select_cipher("vigenere"), set_cipher_type("vigenere")], width=20)
vernam_button = tk.Button(frame_choose_cipher, text="Vernam Cipher", command=lambda: [select_cipher("vernam"), set_cipher_type("vernam")], width=20)

frequency_analysis_button = tk.Button(frame_choose_cipher, text="Frequency Analysis", command=show_frequency_analysis_scene, width=20)

caesar_button.grid(row=0, column=0, padx=10, pady=5)
vigenere_button.grid(row=1, column=0, padx=10, pady=5)
vernam_button.grid(row=2, column=0, padx=10, pady=5)
frequency_analysis_button.grid(row=3, column=0, padx=10, pady=5)


cipher_type_var = tk.StringVar()
cipher_type_var.set("caesar")  # Default selection

frame2 = tk.Frame(frame_cipher_options, bg='turquoise')
frame2.pack()

encrypt_var = tk.BooleanVar()
encrypt_radio = tk.Radiobutton(frame2, text="Encrypt", variable=cipher_type_var, value="encrypt", bg='turquoise', command=toggle_encrypt)
decrypt_radio = tk.Radiobutton(frame2, text="Decrypt", variable=cipher_type_var, value="decrypt", bg='turquoise', command=toggle_decrypt)
encrypt_radio.grid(row=0, column=0, padx=10, pady=5)
decrypt_radio.grid(row=1, column=0, padx=10, pady=5)


back_button_anal = tk.Button(frame2, text="Back to Menu", command=go_back, bg='turquoise')
back_button_anal.grid(row=12, column=0, padx=10, pady=5)


encrypt_var = tk.BooleanVar()
encrypt_var.set(False)
encrypt_check = tk.Checkbutton(frame2, text="Encrypt", variable=encrypt_var, offvalue=False, onvalue=True, bg='turquoise', command=toggle_encrypt)
encrypt_check.grid(row=0, column=0, padx=10, pady=5)

decrypt_var = tk.BooleanVar()
decrypt_var.set(False)
decrypt_check = tk.Checkbutton(frame2, text="Decrypt", variable=decrypt_var, offvalue=False, onvalue=True, bg='turquoise', command=toggle_decrypt)
decrypt_check.grid(row=1, column=0, padx=10, pady=5)

input_label = tk.Label(frame2, text="Input File:", bg='turquoise')
input_label.grid(row=2, column=0, sticky='w', padx=10, pady=5)

input_entry = tk.Entry(frame2, width=40)
input_entry.grid(row=3, column=0, padx=10, pady=5)


input_button = tk.Button(frame2, text="Browse", command=open_file)
input_button.grid(row=3, column=1, padx=10, pady=5)

output_label = tk.Label(frame2, text="Output File:", bg='turquoise')
output_label.grid(row=4, column=0, sticky='w', padx=10, pady=5)


output_entry = tk.Entry(frame2, width=40)
output_entry.grid(row=5, column=0, padx=10, pady=5)

output_button = tk.Button(frame2, text="Browse", command=save_file)
output_button.grid(row=5, column=1, padx=10, pady=5)

shift_label = tk.Label(frame2, text="Shift Value:", bg='turquoise')
shift_label.grid(row=6, column=0, sticky='w', padx=10, pady=5)

shift_entry = tk.Entry(frame2)
shift_entry.grid(row=7, column=0, padx=10, pady=5)

res_label = tk.Label(frame2, text="")
res_label.grid(row=15, column=0)


russian_var = tk.BooleanVar()
russian_check = tk.Checkbutton(frame2, text="Russian Alphabet", variable=russian_var, bg='turquoise', command=toggle_russian)
russian_check.grid(row=8, column=0, padx=10, pady=5)

ascii_range_var = tk.BooleanVar()
ascii_range_check = tk.Checkbutton(frame2, text="English Alphabet", variable=ascii_range_var, bg='turquoise', command=toggle_ascii_range)
ascii_range_check.grid(row=9, column=0, padx=10, pady=5)

key_label = tk.Label(frame2, text="Vigenere Key / Vernam Key:", bg='turquoise')
key_label.grid(row=10, column=0, sticky='w', padx=10, pady=5)

key_entry = tk.Entry(frame2)
key_entry.grid(row=11, column=0, padx=10, pady=5)

back_button = tk.Button(frame2, text="Back to Menu", command=go_back)
back_button.grid(row=12, column=0, padx=10, pady=5)

process_button = tk.Button(frame2, text="Process", command=process)
process_button.grid(row=12, column=1, padx=10, pady=5)

result_label = tk.Label(frame2, text="", bg='turquoise')
result_label.grid(row=6, column=1)
language_frame = tk.Frame(frame_frequency_analysis)
language_frame.pack()

# Language selection label
language_label = tk.Label(language_frame, text="Select Language:")
language_label.pack(side="left")

back_button = tk.Button(frame_frequency_analysis, text="Back to Menu", command=go_back_to_menu)
back_button.pack(side=tk.TOP, padx=10, pady=5)

# Language selection dropdown
languages = ["Russian", "English"]
selected_language = tk.StringVar()
selected_language.set("Russian")
language_dropdown = tk.OptionMenu(language_frame, selected_language, *languages)
language_dropdown.pack(side="left")

# Create a text input field
input_text_label = tk.Label(frame_frequency_analysis, text="Enter Ciphertext:")
input_text_label.pack()

input_text = tk.Text(frame_frequency_analysis, height=10, width=40)
input_text.pack()

# Create an 'Analyze' button
analyze_button = tk.Button(frame_frequency_analysis, text="Analyze", command=analyze_button_clicked)
analyze_button.pack()

# Create a label to display the result
result_label = tk.Label(frame_frequency_analysis, text="")
result_label.pack()

app.mainloop()