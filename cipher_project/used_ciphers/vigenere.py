class VigenereCipher:

    @staticmethod
    def encrypt(text, key, russian=False, ascii_range=False):
        result = ''
        key_length = len(key)
        i = 0  # Initialize a counter for the key

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

            shift = ord(key[i]) - ord(start_char)

            shifted_char = ord(char) - start + shift
            alphabet_size = ord(end_char) - ord(start_char) + 1
            shifted_char %= alphabet_size
            result += chr(start + shifted_char)

            i = (i + 1) % key_length

        return result

    @staticmethod
    def decrypt(ciphertext, key, russian=False, ascii_range=False):
        result = ''
        key_length = len(key)
        i = 0  # Initialize a counter for the key

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

            shift = ord(key[i]) - ord(start_char)

            shifted_char = ord(char) - start - shift
            alphabet_size = ord(end_char) - ord(start_char) + 1
            shifted_char = (shifted_char + alphabet_size) % alphabet_size

            result += chr(start + shifted_char)

            i = (i + 1) % key_length

        return result

    @staticmethod
    def encrypt_vigenere(input_file, output_file, key, russian, ascii_range):
        with open(input_file, 'r', encoding='utf-8') as file:
            plaintext = file.read()
            encrypted_text = VigenereCipher.encrypt(plaintext, key, russian, ascii_range)
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(encrypted_text)

    @staticmethod
    def decrypt_vigenere(input_file, output_file, key, russian, ascii_range):
        with open(input_file, 'r', encoding='utf-8') as file:
            encrypted_text = file.read()
            decrypted_text = VigenereCipher.decrypt(encrypted_text, key, russian, ascii_range)
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(decrypted_text)