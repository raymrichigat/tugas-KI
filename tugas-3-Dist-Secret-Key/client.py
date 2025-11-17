#!/usr/bin/env python3
"""
DES Encrypted Communication - Client
Client for encrypted communication using DES algorithm + RSA key distribution
"""

import socket
import secrets
from des_crypto import des_encrypt, des_decrypt

PORT = 65432

# --- Helper untuk komunikasi berbasis line saat key exchange -----------------

def recv_line(sock):
    """Menerima 1 baris ASCII yang diakhiri newline '\\n'."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed while waiting for line")
        data += chunk
    return data.decode("ascii").strip()

# --- RSA-based key distribution (client side) --------------------------------

def rsa_key_exchange_client(client_socket) -> bytes:
    """
    RSA key distribution di sisi client.

    1. Terima public key (e, n) dari server.
    2. Generate DES session key 8 byte (random).
    3. Encrypt key dengan RSA pakai public key.
    4. Kirim ciphertext (decimal + newline) ke server.
    5. Return DES key (bytes) untuk dipakai DES.
    """
    print("🔐 Starting RSA key exchange (client)...")
    
    # 1) Terima public key dari server
    e_str = recv_line(client_socket)
    n_str = recv_line(client_socket)
    e = int(e_str)
    n = int(n_str)
    print(f"  ← Received RSA public key: e = {e}, n = {n}")
    
    # 2) Generate DES key random (8 byte)
    key_bytes = secrets.token_bytes(8)
    print(f"  🔑 Generated DES session key (hex): {key_bytes.hex().upper()}")
    
    # 3) Konversi ke integer dan encrypt dengan RSA
    m = int.from_bytes(key_bytes, byteorder="big")
    cipher_int = pow(m, e, n)
    
    # 4) Kirim ciphertext ke server sebagai string decimal
    client_socket.sendall(f"{cipher_int}\n".encode("ascii"))
    print(f"  → Sent encrypted DES key (integer): {cipher_int}")
    
    print("✅ RSA key exchange DONE.\n")
    return key_bytes

# --- Main client logic -------------------------------------------------------

def main():
    print("=" * 60)
    print("       DES ENCRYPTED COMMUNICATION - CLIENT")
    print("=" * 60)
    
    # Alamat server
    host = input("Enter server IP address [localhost]: ").strip()
    if not host:
        host = "localhost"
    
    print("RSA public-key distribution of DES secret key is ENABLED.")
    print("Both parties do NOT know the DES key beforehand.\n")
    
    # Connect ke server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            print(f"\n⏳ Connecting to {host}:{PORT}...")
            client_socket.connect((host, PORT))
            print(f"✓ Connected to server at {host}:{PORT}")
            
            # --- Phase 0: RSA key distribution → dapat DES key ----------------
            try:
                key_bytes = rsa_key_exchange_client(client_socket)
            except Exception as e:
                print(f"❌ RSA key exchange failed: {e}")
                return
            
            print("\n" + "=" * 60)
            print("Communication established. You speak first.")
            print("Type 'exit' to end the conversation.")
            print("=" * 60 + "\n")
            
            while True:
                # Kirim pesan
                message = input("Your message: ")
                
                # Enkripsi pesan
                message_bytes = message.encode("utf-8")
                encrypted_msg = des_encrypt(message_bytes, key_bytes)
                
                print(f"🔒 Sending (Encrypted): {encrypted_msg.hex().upper()}")
                
                # Kirim ciphertext
                client_socket.sendall(encrypted_msg)
                
                # Jika client mau exit
                if message.lower() == "exit":
                    print("✓ You ended the conversation.")
                    break
                
                print()
                
                # Terima balasan
                print("⏳ Waiting for server's reply...")
                encrypted_data = client_socket.recv(4096)
                
                if not encrypted_data:
                    print("\n✗ Server disconnected.")
                    break
                
                # Tampilkan ciphertext
                print(f"📩 Received (Encrypted): {encrypted_data.hex().upper()}")
                
                # Dekripsi balasan
                try:
                    decrypted_msg = des_decrypt(encrypted_data, key_bytes)
                    reply = decrypted_msg.decode("utf-8", errors="ignore")
                    print(f"🔓 Server's Reply: {reply}")
                except Exception as e:
                    print(f"❌ Decryption error: {e}")
                    continue
                
                # Jika server mau exit
                if reply.lower() == "exit":
                    print("✓ Server has ended the conversation.")
                    break
                
                print("-" * 60)
                
        except ConnectionRefusedError:
            print(f"\n❌ Could not connect to server at {host}:{PORT}")
            print("   Make sure the server is running.")
        except KeyboardInterrupt:
            print("\n\n✗ Client interrupted by user.")
        except Exception as e:
            print(f"\n❌ Error: {e}")
    
    print("\n" + "=" * 60)
    print("       Connection closed.")
    print("=" * 60)

if __name__ == "__main__":
    main()
