from cipher_project.used_ciphers import frequency_languages
class CipherAnalysis:
    @staticmethod
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

    @staticmethod
    def caesar_frequency_analysis(ciphertext, language_frequencies):
        shift_range = range(1, 33) if language_frequencies == frequency_languages.russian_frequencies else range(1, 27)

        best_shift = None
        best_score = float('-inf')

        for shift in shift_range:
            decrypted_text = ''
            for char in ciphertext:
                if char.isalpha():
                    shifted_char = chr(((ord(char.lower()) - ord('а') - shift) % 32) + ord('а')) \
                        if language_frequencies == frequency_languages.russian_frequencies \
                        else chr(((ord(char.lower()) - ord('a') - shift) % 26) + ord('a'))
                    decrypted_text += shifted_char if char.islower() else shifted_char.upper()
                else:
                    decrypted_text += char

            frequencies = CipherAnalysis.calculate_letter_frequencies(decrypted_text)
            score = sum(language_frequencies.get(char, 0) * frequencies[char] for char in frequencies)
            if score > best_score:
                best_score = score
                best_shift = shift

        return best_shift
