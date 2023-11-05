

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
        shift_range = range(1, 27)  # Shift range for English (26 letters)

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