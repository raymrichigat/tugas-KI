#!/usr/bin/env python3
"""
DES Communication Client
Client yang terhubung ke server dan dapat berkomunikasi dengan enkripsi DES
"""

import socket
import threading
import sys

# Import fungsi DES dari file sebelumnya
from des_crypto import (
    convert_text_to_bits, 
    convert_bits_to_text,
    convert_hex_to_bits,
    convert_bits_to_hex,
    process_single_block,
    create_round_keys
)

class DESClient:
    def __init__(self, host='localhost', port=5555, key='DESKEY12'):
        self.host = host
        self.port = port
        self.key = key
        self.socket = None
        self.running = False
        
        # Validasi key
        if len(self.key) != 8:
            raise ValueError("Key harus 8 karakter!")
        
        self.key_bits = convert_text_to_bits(self.key)
    
    def connect(self):
        """Menghubungkan ke server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.host, self.port))
            self.running = True
            
            print("=" * 60)
            print("  DES COMMUNICATION CLIENT")
            print("=" * 60)
            print(f"✓ Terhubung ke server {self.host}:{self.port}")
            print(f"Shared Key: {self.key}")
            print("-" * 60)
            print("Komunikasi dimulai! Ketik pesan dan tekan Enter untuk mengirim.")
            print("Ketik 'EXIT' untuk mengakhiri koneksi.")
            print("-" * 60)
            
            # Jalankan thread untuk menerima pesan
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            # Jalankan pengiriman pesan di main thread
            self.send_messages()
            
        except Exception as e:
            print(f"✗ Error koneksi: {e}")
        finally:
            self.disconnect()
    
    def encrypt_message(self, plaintext):
        """Enkripsi pesan menggunakan DES"""
        # Padding jika perlu
        remainder = len(plaintext) % 8
        if remainder != 0:
            padding = 8 - remainder
            plaintext += '\0' * padding
        
        message_bits = convert_text_to_bits(plaintext)
        encrypted_result = []
        
        position = 0
        while position < len(message_bits):
            block_data = message_bits[position:position+64]
            cipher_block = process_single_block(block_data, self.key_bits, True)
            encrypted_result.extend(cipher_block)
            position += 64
        
        return convert_bits_to_hex(encrypted_result)
    
    def decrypt_message(self, ciphertext_hex):
        """Dekripsi pesan menggunakan DES"""
        cipher_bits = convert_hex_to_bits(ciphertext_hex)
        decrypted_result = []
        
        position = 0
        while position < len(cipher_bits):
            block_data = cipher_bits[position:position+64]
            plain_block = process_single_block(block_data, self.key_bits, False)
            decrypted_result.extend(plain_block)
            position += 64
        
        plaintext = convert_bits_to_text(decrypted_result)
        return plaintext.rstrip('\0')
    
    def receive_messages(self):
        """Thread untuk menerima pesan dari server"""
        while self.running:
            try:
                data = self.socket.recv(4096).decode('utf-8')
                if not data:
                    print("\n✗ Server terputus.")
                    self.running = False
                    break
                
                if data == "EXIT":
                    print("\n✗ Server mengakhiri koneksi.")
                    self.running = False
                    break
                
                # Dekripsi pesan yang diterima
                try:
                    decrypted = self.decrypt_message(data)
                    print(f"\n{'─' * 60}")
                    print(f"📩 PESAN DITERIMA (Encrypted): {data}")
                    print(f"🔓 PESAN DITERIMA (Decrypted): {decrypted}")
                    print(f"{'─' * 60}")
                    print(">> Balas: ", end="", flush=True)
                except Exception as e:
                    print(f"\n✗ Error dekripsi: {e}")
                    
            except Exception as e:
                if self.running:
                    print(f"\n✗ Error receiving: {e}")
                break
    
    def send_messages(self):
        """Mengirim pesan ke server"""
        while self.running:
            try:
                message = input(">> Kirim: ")
                
                if message.upper() == "EXIT":
                    self.socket.send("EXIT".encode('utf-8'))
                    print("\n✓ Koneksi diakhiri.")
                    self.running = False
                    break
                
                if message.strip():
                    # Enkripsi pesan
                    encrypted = self.encrypt_message(message)
                    self.socket.send(encrypted.encode('utf-8'))
                    
                    print(f"{'─' * 60}")
                    print(f"📤 PESAN TERKIRIM (Original): {message}")
                    print(f"🔒 PESAN TERKIRIM (Encrypted): {encrypted}")
                    print(f"{'─' * 60}\n")
                    
            except Exception as e:
                if self.running:
                    print(f"\n✗ Error sending: {e}")
                break
    
    def disconnect(self):
        """Memutuskan koneksi"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("\n" + "=" * 60)
        print("  Client terputus.")
        print("=" * 60)

def main():
    print("\n" + "=" * 60)
    print("  SETUP DES CLIENT")
    print("=" * 60)
    
    # Input konfigurasi
    host = input("IP Server [default: localhost]: ").strip()
    host = host if host else "localhost"
    
    port = input("Port server [default: 5555]: ").strip()
    port = int(port) if port else 5555
    
    key = input("Shared Key (8 karakter) [default: DESKEY12]: ").strip()
    key = key if key and len(key) == 8 else "DESKEY12"
    
    if len(key) != 8:
        print("\n✗ Error: Key harus 8 karakter!")
        return
    
    try:
        client = DESClient(host=host, port=port, key=key)
        client.connect()
    except KeyboardInterrupt:
        print("\n\n✓ Client dihentikan oleh user.")
    except Exception as e:
        print(f"\n✗ Error: {e}")

if __name__ == "__main__":
    main()
