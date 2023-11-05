import tkinter as tk
from tkinter import filedialog
from python_project.cipher_project.used_ciphers.caesar import  CaesarCipher
from python_project.cipher_project.used_ciphers.vigenere import VigenereCipher
from python_project.cipher_project.used_ciphers.vernam import  VernamCipher
from python_project.cipher_project.used_ciphers import frequencies


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
        CaesarCipher.encrypt_file(input_file, output_file, shift, russian, ascii_range)
        res_label.config(text="Caesar Encryption done! File saved as " + output_file)
    else:
        CaesarCipher.decrypt_file(input_file, output_file, shift, russian, ascii_range)
        res_label.config(text="Caesar Decryption done! File saved as " + output_file)

def process_vigenere():
    input_file = input_entry.get()
    output_file = output_entry.get()
    key = key_entry.get()
    russian = russian_var.get()
    ascii_range = ascii_range_var.get()

    if encrypt_var.get():
        VigenereCipher.encrypt_vigenere(input_file, output_file, key, russian, ascii_range)
        res_label.config(text="Vigenere Encryption done! File saved as " + output_file)
    else:
        VigenereCipher.decrypt_vigenere(input_file, output_file, key, russian, ascii_range)
        res_label.config(text="Vigenere Decryption done! File saved as " + output_file)

def process_vernam():
    input_file = input_entry.get()
    output_file = output_entry.get()
    key = key_entry.get()

    if encrypt_var.get():
        VernamCipher.vernam_cipher(input_file, output_file, key)
        res_label.config(text="Vernam Encryption done! File saved as " + output_file)
    else:
        VernamCipher.vernam_cipher(input_file, output_file, key)
        res_label.config(text="Vernam Decryption done! File saved as " + output_file)


def analyze_button_clicked():
    ciphertext = input_text.get("1.0", "end-1c")
    language = selected_language.get()
    if language == "Russian":
        language_frequencies = frequencies.russian_frequencies
    else:
        language_frequencies = frequencies.english_frequencies
    best_shift = frequencies.caesar_frequency_analysis(ciphertext, language_frequencies)
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
# Здесь добавьте кнопку "Анализ частоты"
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
ascii_range_check = tk.Checkbutton(frame2, text="16-128 ASCII Range", variable=ascii_range_var, bg='turquoise', command=toggle_ascii_range)
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