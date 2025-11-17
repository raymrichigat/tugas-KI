#!/usr/bin/env python3
"""
DES Encrypted Communication - Server
Server for encrypted communication using DES algorithm + RSA key distribution
"""

import socket
from des_crypto import des_encrypt, des_decrypt

# Configuration
HOST = '0.0.0.0'
PORT = 65432

# --- RSA PARAMETERS (demo, not for real-world security) ----------------------

# Dua bilangan prima besar (fix untuk demo, boleh kamu tulis di laporan)
RSA_P = 5666448961
RSA_Q = 5180577959

# Modulus dan totient
RSA_N = RSA_P * RSA_Q
RSA_PHI = (RSA_P - 1) * (RSA_Q - 1)

# Eksponen publik
RSA_E = 65537

def _egcd(a, b):
    """Extended Euclidean Algorithm (helper untuk modular inverse)."""
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def _modinv(a, m):
    """Modular inverse dari a (mod m)."""
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse for RSA_E modulo phi(N)")
    return x % m

# Eksponen privat
RSA_D = _modinv(RSA_E, RSA_PHI)

# --- Helper untuk komunikasi berbasis line saat key exchange -----------------

def recv_line(conn):
    """Menerima 1 baris ASCII yang diakhiri newline '\\n'."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed while waiting for line")
        data += chunk
    return data.decode("ascii").strip()

# --- RSA-based key distribution ---------------------------------------------

def rsa_key_exchange_server(conn) -> bytes:
    """
    RSA key distribution di sisi server.

    1. Server kirim public key (e, n) ke client (2 baris).
    2. Client generate DES key 8 byte, encrypt pakai RSA, kirim ciphertext (decimal).
    3. Server decrypt pakai d → dapat DES key (bytes).
    """
    print("🔐 Starting RSA key exchange (server)...")
    print(f"  Public key: e = {RSA_E}, n = {RSA_N}")
    
    # 1) Kirim public key ke client
    conn.sendall(f"{RSA_E}\n".encode("ascii"))
    conn.sendall(f"{RSA_N}\n".encode("ascii"))
    print("  → Sent RSA public key to client.")
    
    # 2) Terima encrypted DES key (dalam bentuk integer decimal)
    enc_key_str = recv_line(conn)
    cipher_int = int(enc_key_str)
    print(f"  ← Received encrypted DES key (integer): {cipher_int}")
    
    # 3) RSA decrypt dengan private key
    shared_int = pow(cipher_int, RSA_D, RSA_N)
    
    # Konversi integer kembali ke 8-byte DES key
    key_bytes = shared_int.to_bytes(8, byteorder="big")
    print(f"  🔑 Derived DES session key (hex): {key_bytes.hex().upper()}")
    print("✅ RSA key exchange DONE.\n")
    
    return key_bytes

# --- Main server logic ------------------------------------------------------

def main():
    print("=" * 60)
    print("       DES ENCRYPTED COMMUNICATION - SERVER")
    print("=" * 60)
    
    print("RSA public-key distribution of DES secret key is ENABLED.")
    print("Both parties do NOT know the DES key beforehand.\n")
    
    # Create socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        
        print(f"\n✓ Server is listening on {HOST}:{PORT}")
        print("⏳ Waiting for client connection...")
        
        conn, addr = server_socket.accept()
        
        with conn:
            print(f"✓ Client connected from {addr[0]}:{addr[1]}")
            
            # --- Phase 0: RSA key distribution → dapat DES key ----------------
            try:
                key_bytes = rsa_key_exchange_server(conn)
            except Exception as e:
                print(f"❌ RSA key exchange failed: {e}")
                return
            
            print("\n" + "=" * 60)
            print("Communication established. Client will speak first.")
            print("Type 'exit' to end the conversation.")
            print("=" * 60 + "\n")
            
            try:
                while True:
                    # Receive encrypted message from client
                    print("⏳ Waiting for client's message...")
                    encrypted_data = conn.recv(4096)
                    
                    if not encrypted_data:
                        print("\n✗ Client disconnected.")
                        break
                    
                    # Tampilan ciphertext
                    print(f"📩 Received (Encrypted): {encrypted_data.hex().upper()}")
                    
                    # Dekripsi pesan
                    try:
                        decrypted_msg = des_decrypt(encrypted_data, key_bytes)
                        message = decrypted_msg.decode("utf-8", errors="ignore")
                        print(f"🔓 Decrypted Message: {message}")
                    except Exception as e:
                        print(f"❌ Decryption error: {e}")
                        continue
                    
                    # Jika client mau exit
                    if message.lower() == "exit":
                        print("✓ Client has ended the conversation.")
                        break
                    
                    print()
                    
                    # Kirim balasan
                    reply = input("Your reply: ")
                    
                    # Enkripsi balasan
                    reply_bytes = reply.encode("utf-8")
                    encrypted_reply = des_encrypt(reply_bytes, key_bytes)
                    
                    print(f"🔒 Sending (Encrypted): {encrypted_reply.hex().upper()}")
                    
                    # Kirim balasan terenkripsi
                    conn.sendall(encrypted_reply)
                    
                    # Jika server mau exit
                    if reply.lower() == "exit":
                        print("✓ You ended the conversation.")
                        break
                    
                    print("-" * 60)
                    
            except KeyboardInterrupt:
                print("\n\n✗ Server interrupted by user.")
            except Exception as e:
                print(f"\n❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("       Connection closed. Server shutting down.")
    print("=" * 60)

if __name__ == "__main__":
    main()
