# --- All static permutation and substitution tables used in DES ---
IP_TABLE = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
FP_TABLE = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
E_TABLE = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
S_BOXES = [
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],[0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],[4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],[15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],[3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],[0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],[13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],[13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],[13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],[1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],[13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],[10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],[3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],[14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],[4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],[11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],[10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],[9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],[4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],[13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],[1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],[6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],[1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],[7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],[2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]
P_TABLE = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
PC1_TABLE = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
PC2_TABLE = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# --- Helper Functions ---
def permute(block, table):
    return [block[i - 1] for i in table]

def string_to_bits(text):
    return [int(bit) for char in text for bit in bin(ord(char))[2:].zfill(8)]

def bits_to_string(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        chars.append(chr(int("".join(map(str, byte)), 2)))
    return "".join(chars)

def bits_to_hex(bits):
    """CORRECTED: Converts bits to hex, ensuring proper padding."""
    hex_len = len(bits) // 4
    return hex(int("".join(map(str, bits)), 2))[2:].upper().zfill(hex_len)

def hex_to_bits(hex_str):
    return [int(b) for b in bin(int(hex_str, 16))[2:].zfill(len(hex_str) * 4)]

def xor(bits1, bits2):
    return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

def left_shift(bits, n):
    return bits[n:] + bits[:n]

# --- Core DES Functions ---
def generate_subkeys(key_bits):
    permuted_key = permute(key_bits, PC1_TABLE)
    left_half, right_half = permuted_key[:28], permuted_key[28:]
    subkeys = []
    for i in range(16):
        left_half = left_shift(left_half, SHIFT_SCHEDULE[i])
        right_half = left_shift(right_half, SHIFT_SCHEDULE[i])
        combined_key = left_half + right_half
        subkeys.append(permute(combined_key, PC2_TABLE))
    return subkeys

def feistel_function(right_half, subkey):
    expanded_bits = permute(right_half, E_TABLE)
    xored_bits = xor(expanded_bits, subkey)
    s_box_output = []
    for i in range(8):
        chunk = xored_bits[i*6:(i+1)*6]
        row = int(str(chunk[0]) + str(chunk[5]), 2)
        col = int("".join(map(str, chunk[1:5])), 2)
        val = S_BOXES[i][row][col]
        s_box_output.extend([int(b) for b in bin(val)[2:].zfill(4)])
    return permute(s_box_output, P_TABLE)

def des_process_block(input_block, key_bits, mode='encrypt'):
    if mode == 'encrypt':
        subkeys = generate_subkeys(key_bits)
    else:  # decrypt
        subkeys = generate_subkeys(key_bits)[::-1]
    
    permuted_block = permute(input_block, IP_TABLE)
    left_half, right_half = permuted_block[:32], permuted_block[32:]
    
    for i in range(16):
        f_result = feistel_function(right_half, subkeys[i])
        left_half, right_half = right_half, xor(left_half, f_result)
        
    final_block = right_half + left_half
    return permute(final_block, FP_TABLE)

# --- Main Execution ---

if __name__ == "__main__":
    print("--- DES Encryption & Decryption CLI Tool ---")
    print("WARNING: DES is insecure. This tool is for educational purposes only.")
    
    while True:
        choice = input("\nChoose an option:\n 1. Encrypt\n 2. Decrypt\n 3. Quit\nEnter your choice (1, 2, or 3): ")

        if choice == '3':
            print("Exiting.")
            break
        
        elif choice in ['1', '2']:
            key = input("Enter the 8-character secret key: ")
            if len(key) != 8:
                print("Error: Key must be exactly 8 characters long.")
                continue

            if choice == '1':
                # --- ENCRYPTION ---
                plaintext = input("Enter the message to encrypt: ")
                padding_needed = 8 - (len(plaintext) % 8)
                if padding_needed != 8:
                    plaintext += '\0' * padding_needed
                
                key_bits = string_to_bits(key)
                plaintext_bits = string_to_bits(plaintext)
                full_ciphertext_bits = []
                
                for i in range(0, len(plaintext_bits), 64):
                    block = plaintext_bits[i:i+64]
                    encrypted_block = des_process_block(block, key_bits, mode='encrypt')
                    full_ciphertext_bits.extend(encrypted_block)
                
                ciphertext_hex = bits_to_hex(full_ciphertext_bits)
                print("\n--- Encryption Complete ---")
                print(f"Ciphertext (Hex): {ciphertext_hex}")

            elif choice == '2':
                # --- DECRYPTION ---
                ciphertext_hex = input("Enter the ciphertext to decrypt (in Hex): ").strip()
                if len(ciphertext_hex) % 16 != 0:
                    print("Error: Invalid ciphertext length. Must be a multiple of 16 hex characters.")
                    continue
                
                try:
                    key_bits = string_to_bits(key)
                    ciphertext_bits = hex_to_bits(ciphertext_hex)
                    full_decrypted_bits = []
                    
                    for i in range(0, len(ciphertext_bits), 64):
                        block = ciphertext_bits[i:i+64]
                        decrypted_block = des_process_block(block, key_bits, mode='decrypt')
                        full_decrypted_bits.extend(decrypted_block)
                    
                    decrypted_text = bits_to_string(full_decrypted_bits)
                    result = decrypted_text.rstrip('\0') # Remove padding
                    print("\n--- Decryption Complete ---")
                    print(f"Decrypted Plaintext: '{result}'")
                except ValueError:
                    print("\nError: Invalid hexadecimal string provided for ciphertext.")
                except Exception as e:
                    print(f"An unexpected error occurred: {e}")

        else:
            print("Invalid choice. Please enter 1, 2, or 3.")