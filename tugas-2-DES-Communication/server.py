#!/usr/bin/env python3
"""
DES Encrypted Communication - Server
Simple server for encrypted communication using DES algorithm
"""

import socket
from des_crypto import des_encrypt, des_decrypt

# Configuration
HOST = '0.0.0.0'
PORT = 65432

def main():
    print("=" * 60)
    print("       DES ENCRYPTED COMMUNICATION - SERVER")
    print("=" * 60)
    
    # Get encryption key
    while True:
        key = input("Enter 8-character encryption key: ").strip()
        if len(key) == 8:
            break
        print("❌ Key must be exactly 8 characters!")
    
    key_bytes = key.encode('utf-8')
    
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
                    
                    # Display received ciphertext
                    print(f"📩 Received (Encrypted): {encrypted_data.hex().upper()}")
                    
                    # Decrypt the message
                    try:
                        decrypted_msg = des_decrypt(encrypted_data, key_bytes)
                        message = decrypted_msg.decode('utf-8', errors='ignore')
                        print(f"🔓 Decrypted Message: {message}")
                    except Exception as e:
                        print(f"❌ Decryption error: {e}")
                        continue
                    
                    # Check if client wants to exit
                    if message.lower() == 'exit':
                        print("✓ Client has ended the conversation.")
                        break
                    
                    print()
                    
                    # Send reply
                    reply = input("Your reply: ")
                    
                    # Encrypt reply
                    reply_bytes = reply.encode('utf-8')
                    encrypted_reply = des_encrypt(reply_bytes, key_bytes)
                    
                    print(f"🔒 Sending (Encrypted): {encrypted_reply.hex().upper()}")
                    
                    # Send encrypted reply
                    conn.sendall(encrypted_reply)
                    
                    # Check if server wants to exit
                    if reply.lower() == 'exit':
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
