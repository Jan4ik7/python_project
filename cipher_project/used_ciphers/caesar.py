class CaesarCipher:
    @staticmethod
    def encrypt(text, shift, russian=False, ascii_range=False):
        result = ''
        for char in text:
            start_char, end_char, start_upper, end_upper = ('а', 'я', 'А', 'Я') if russian else ('a', 'z', 'A', 'Z')
            if char == 'ё' and russian:
                start_char, end_char, start_upper, end_upper = 'а', 'я', 'А', 'Я'

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


    @classmethod
    def encrypt_file(cls, input_file, output_file, shift, russian, ascii_range):
        with open(input_file, 'r', encoding='utf-8') as file:
            plaintext = file.read()
            encrypted_text = cls.encrypt(plaintext, shift, russian, ascii_range)
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(encrypted_text)

    @classmethod
    def decrypt_file(cls, input_file, output_file, shift, russian, ascii_range):
        with open(input_file, 'r', encoding='utf-8') as file:
            encrypted_text = file.read()
            decrypted_text = cls.encrypt(encrypted_text, -shift, russian, ascii_range)
        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(decrypted_text)
