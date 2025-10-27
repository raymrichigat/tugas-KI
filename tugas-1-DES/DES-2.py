# Tabel Permutasi Awal
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

# Tabel Permutasi Final
FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

# Permuted Choice 1
PC_1 = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]

# Permuted Choice 2
PC_2 = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]

# Jumlah shift per round
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# Expansion Table
E_TABLE = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S-Box Tables
SBOX = [
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
]

# Permutation Table
PERM = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]

def hex_to_bin(hex_str):
    binary = bin(int(hex_str, 16))[2:]
    return binary.zfill(len(hex_str) * 4)

def bin_to_hex(bin_str):
    hex_val = hex(int(bin_str, 2))[2:]
    return hex_val.zfill(len(bin_str) // 4)

def text_to_bin(text):
    return ''.join(format(ord(char), '08b') for char in text)

def bin_to_text(bin_str):
    text = ''
    for i in range(0, len(bin_str), 8):
        text += chr(int(bin_str[i:i+8], 2))
    return text

def format_binary(bin_str):
    result = []
    for i in range(0, len(bin_str), 4):
        result.append(bin_str[i:i+4])
    return ' '.join(result)

def int_to_bin(num, length):
    return bin(num)[2:].zfill(length)

def apply_permutation(data, perm_table, output_len):
    output = ''
    for i in range(output_len):
        output += data[perm_table[i] - 1]
    return output

def rotate_left(data, shifts):
    return data[shifts:] + data[:shifts]

def xor_operation(bits1, bits2):
    result = ''
    for i in range(len(bits1)):
        if bits1[i] == bits2[i]:
            result += '0'
        else:
            result += '1'
    return result

def sbox_substitution(input_bits):
    output = ''
    for box_num in range(8):
        start = box_num * 6
        block = input_bits[start:start+6]
        row_bits = block[0] + block[5]
        col_bits = block[1:5]
        row = int(row_bits, 2)
        col = int(col_bits, 2)
        val = SBOX[box_num][row][col]
        output += int_to_bin(val, 4)
    return output

def feistel_function(right_half, subkey):
    expanded = apply_permutation(right_half, E_TABLE, 48)
    xored = xor_operation(expanded, subkey)
    substituted = sbox_substitution(xored)
    permuted = apply_permutation(substituted, PERM, 32)
    return permuted

def create_subkey(c_half, d_half, round_num):
    shift_amount = SHIFT_SCHEDULE[round_num]
    c_half = rotate_left(c_half, shift_amount)
    d_half = rotate_left(d_half, shift_amount)
    combined = c_half + d_half
    subkey = apply_permutation(combined, PC_2, 48)
    return c_half, d_half, subkey

def generate_master_key():
    import random
    random.seed(19)
    key_hex = ''
    for _ in range(16):
        key_hex += random.choice('0123456789ABCDEF')
    return key_hex

def des_round(left, right, subkey):
    f_result = feistel_function(right, subkey)
    new_right = xor_operation(left, f_result)
    return right, new_right

def main():
    while True:
        master_key = generate_master_key()
        print(f"Initial Key: {master_key}")
        
        key_binary = hex_to_bin(master_key)
        print(f"Binary Key: {format_binary(key_binary)}\n")
        
        key_permuted = apply_permutation(key_binary, PC_1, 56)
        c_half = key_permuted[:28]
        d_half = key_permuted[28:]
        
        input_type = input("Format Input (hex/text): ").strip().lower()
        
        if input_type == 'hex':
            plain = input("Enter Plaintext (16 hex digits): ").strip()
            if len(plain) != 16 or not all(c in '0123456789abcdefABCDEF' for c in plain):
                print("Invalid Plaintext\n")
                break
            plaintext_bin = hex_to_bin(plain)
            print(f"Binary Plaintext: {format_binary(plaintext_bin)}\n")
            output_type = 'hex'
        elif input_type == 'text':
            plain = input("Enter Plaintext (8 characters): ")
            if len(plain) != 8:
                print("Invalid Plaintext\n")
                break
            plaintext_bin = text_to_bin(plain)
            print(f"Binary Plaintext: {format_binary(plaintext_bin)}\n")
            output_type = 'text'
        else:
            print("Invalid Format\n")
            break
        
        permuted_text = apply_permutation(plaintext_bin, IP, 64)
        L = permuted_text[:32]
        R = permuted_text[32:]
        
        subkeys = []
        print("Encryption:")
        for round_idx in range(16):
            print(f"Round {round_idx + 1}:")
            c_half, d_half, subkey = create_subkey(c_half, d_half, round_idx)
            subkeys.append(subkey)
            L, R = des_round(L, R, subkey)
            print(f"Left (R{round_idx + 1}): {format_binary(L)}")
            print(f"Right (R{round_idx + 1}): {format_binary(R)}")
            print(f"Key: {format_binary(c_half + d_half)}\n")
        
        combined = R + L
        ciphertext_bin = apply_permutation(combined, FP, 64)
        
        print(f"Binary Ciphertext: {format_binary(ciphertext_bin)}")
        if output_type == 'hex':
            print(f"Ciphertext: {bin_to_hex(ciphertext_bin).upper()}\n")
        else:
            print(f"Ciphertext: {bin_to_text(ciphertext_bin)}\n")
        
        L = R
        R = combined[:32]
        
        print("Decryption:")
        for round_idx in range(16):
            print(f"Round {16 - round_idx}:")
            L, R = des_round(L, R, subkeys[15 - round_idx])
            print(f"Left (R{16 - round_idx}): {format_binary(L)}")
            print(f"Right (R{16 - round_idx}): {format_binary(R)}\n")
        
        decrypted_bin = apply_permutation(R + L, FP, 64)
        if output_type == 'hex':
            print(f"Plaintext: {bin_to_hex(decrypted_bin).upper()}\n")
        else:
            print(f"Plaintext: {bin_to_text(decrypted_bin)}\n")
        
        continue_choice = input("Continue? (y/n): ").strip().lower()
        if continue_choice == 'y':
            print()
            continue
        elif continue_choice == 'n':
            break
        else:
            print("Invalid Input")
            break

if __name__ == "__main__":
    main()