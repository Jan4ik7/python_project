class VernamCipher:
    def vernam_cipher(text, key):
        result = ''
        if len(key) < len(text):
            raise ValueError("Ключ должен быть не короче текста.")
            messagebox.showerror("Ошибка", str(e))

        for char, key_char in zip(text, key):
            encrypted_char = ord(char) ^ ord(key_char)
            result += chr(encrypted_char)

        return result

    def encrypt_vernam(input_file, output_file, key):
        with open(input_file, 'r', encoding='utf-8') as file:
            plaintext = file.read()
            encrypted_text = VernamChiper.vernam_cipher(plaintext, key)
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(encrypted_text)

    def decrypt_vernam(input_file, output_file, key):
        with open(input_file, 'r', encoding='utf-8') as file:
            encrypted_text = file.read()
            decrypted_text = VernamChiper.vernam_cipher(encrypted_text, key)
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(decrypted_text)
