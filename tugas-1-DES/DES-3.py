# Tabel permutasi dan substitusi DES
INITIAL_PERMUTATION = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FINAL_PERMUTATION = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

EXPANSION_TABLE = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

SUBSTITUTION_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

PERMUTATION_BOX = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

PERMUTED_CHOICE_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

PERMUTED_CHOICE_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

def apply_table(data, perm_table):
    result = []
    for idx in perm_table:
        result.append(data[idx - 1])
    return result

def convert_text_to_bits(text):
    bit_list = []
    for character in text:
        byte_val = ord(character)
        binary_str = bin(byte_val)[2:].zfill(8)
        for bit in binary_str:
            bit_list.append(int(bit))
    return bit_list

def convert_bits_to_text(bit_array):
    result = []
    idx = 0
    while idx < len(bit_array):
        byte_chunk = bit_array[idx:idx+8]
        binary_string = ""
        for b in byte_chunk:
            binary_string += str(b)
        char_code = int(binary_string, 2)
        result.append(chr(char_code))
        idx += 8
    return "".join(result)

def convert_hex_to_bits(hex_string):
    bit_count = len(hex_string) * 4
    int_value = int(hex_string, 16)
    binary = bin(int_value)[2:].zfill(bit_count)
    return [int(b) for b in binary]

def convert_bits_to_hex(bit_array):
    bit_string = ""
    for bit in bit_array:
        bit_string += str(bit)
    hex_len = len(bit_array) // 4
    return hex(int(bit_string, 2))[2:].upper().zfill(hex_len)

def perform_xor(bits_a, bits_b):
    output = []
    for i in range(len(bits_a)):
        output.append(bits_a[i] ^ bits_b[i])
    return output

def rotate_bits(bit_array, shift_amount):
    return bit_array[shift_amount:] + bit_array[:shift_amount]

def create_round_keys(key_bits):
    after_pc1 = apply_table(key_bits, PERMUTED_CHOICE_1)
    c_part = after_pc1[:28]
    d_part = after_pc1[28:]
    
    keys_list = []
    for round_num in range(16):
        shift_val = KEY_SHIFTS[round_num]
        c_part = rotate_bits(c_part, shift_val)
        d_part = rotate_bits(d_part, shift_val)
        merged = c_part + d_part
        round_key = apply_table(merged, PERMUTED_CHOICE_2)
        keys_list.append(round_key)
    
    return keys_list

def run_feistel_func(right_data, key_data):
    expanded = apply_table(right_data, EXPANSION_TABLE)
    xor_result = perform_xor(expanded, key_data)
    
    sbox_output = []
    for box_index in range(8):
        start_pos = box_index * 6
        six_bits = xor_result[start_pos:start_pos+6]
        
        row_bits = str(six_bits[0]) + str(six_bits[5])
        row_num = int(row_bits, 2)
        
        col_str = ""
        for j in range(1, 5):
            col_str += str(six_bits[j])
        col_num = int(col_str, 2)
        
        sbox_value = SUBSTITUTION_BOXES[box_index][row_num][col_num]
        four_bits = bin(sbox_value)[2:].zfill(4)
        for bit_char in four_bits:
            sbox_output.append(int(bit_char))
    
    return apply_table(sbox_output, PERMUTATION_BOX)

def process_single_block(input_data, key_bits, is_encrypt):
    round_keys = create_round_keys(key_bits)
    
    if not is_encrypt:
        round_keys = round_keys[::-1]
    
    after_ip = apply_table(input_data, INITIAL_PERMUTATION)
    left_part = after_ip[:32]
    right_part = after_ip[32:]
    
    for round_idx in range(16):
        feistel_result = run_feistel_func(right_part, round_keys[round_idx])
        new_right = perform_xor(left_part, feistel_result)
        left_part = right_part
        right_part = new_right
    
    combined = right_part + left_part
    return apply_table(combined, FINAL_PERMUTATION)

def main():
    print("=" * 50)
    print("  PROGRAM KRIPTOGRAFI DES")
    print("  Data Encryption Standard")
    print("=" * 50)
    # print("Catatan: Hanya untuk keperluan edukasi\n")
    
    while True:
        print("-" * 50)
        print("MENU UTAMA:")
        print("[1] Enkripsi Pesan")
        print("[2] Dekripsi Pesan")
        print("[3] Exit")
        print("-" * 50)
        user_choice = input(">> Pilihan Anda: ").strip()

        if user_choice == '3':
            print("\n" + "=" * 50)
            print("  Terima kasih telah menggunakan program ini!")
            print("=" * 50)
            break
        
        if user_choice not in ['1', '2']:
            print("\n[!] Input tidak valid! Pilih 1, 2, atau 3.\n")
            continue
        
        print()
        secret_key = input("Masukkan key (8 karakter): ")
        if len(secret_key) != 8:
            print("[!] Error: Key harus 8 karakter!\n")
            continue

        if user_choice == '1':
            message = input("Masukkan plaintext: ")
            
            remainder = len(message) % 8
            if remainder != 0:
                padding = 8 - remainder
                message += '\0' * padding
            
            key_in_bits = convert_text_to_bits(secret_key)
            message_in_bits = convert_text_to_bits(message)
            
            encrypted_result = []
            position = 0
            while position < len(message_in_bits):
                block_data = message_in_bits[position:position+64]
                cipher_block = process_single_block(block_data, key_in_bits, True)
                encrypted_result.extend(cipher_block)
                position += 64
            
            hex_output = convert_bits_to_hex(encrypted_result)
            print("\n" + "=" * 50)
            print("HASIL ENKRIPSI")
            # print("=" * 50)
            print(f"Ciphertext: {hex_output}")
            print("=" * 50 + "\n")

        elif user_choice == '2':
            cipher_hex = input("Masukkan ciphertext (Hex): ").strip()
            
            if len(cipher_hex) % 16 != 0:
                print("[!] Error: Panjang ciphertext harus kelipatan 16 hex!\n")
                continue
            
            try:
                key_in_bits = convert_text_to_bits(secret_key)
                cipher_in_bits = convert_hex_to_bits(cipher_hex)
                
                decrypted_result = []
                position = 0
                while position < len(cipher_in_bits):
                    block_data = cipher_in_bits[position:position+64]
                    plain_block = process_single_block(block_data, key_in_bits, False)
                    decrypted_result.extend(plain_block)
                    position += 64
                
                plaintext = convert_bits_to_text(decrypted_result)
                final_text = plaintext.rstrip('\0')
                
                print("\n" + "=" * 50)
                print("HASIL DEKRIPSI")
                # print("=" * 50)
                print(f"Plaintext: {final_text}")
                print("=" * 50 + "\n")
                
            except ValueError:
                print("\n[!] Error: Format hexadecimal tidak valid!\n")
            except Exception as error:
                print(f"[!] Error: {error}\n")

if __name__ == "__main__":
    main()