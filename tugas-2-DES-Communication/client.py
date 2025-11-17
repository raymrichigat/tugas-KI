#!/usr/bin/env python3
"""
DES Encrypted Communication - Client
Simple client for encrypted communication using DES algorithm
"""

import socket
from des_crypto import des_encrypt, des_decrypt

PORT = 65432

def main():
    print("=" * 60)
    print("       DES ENCRYPTED COMMUNICATION - CLIENT")
    print("=" * 60)
    
    # Get server address
    host = input("Enter server IP address [localhost]: ").strip()
    if not host:
        host = 'localhost'
    
    # Get encryption key
    while True:
        key = input("Enter 8-character encryption key: ").strip()
        if len(key) == 8:
            break
        print("❌ Key must be exactly 8 characters!")
    
    key_bytes = key.encode('utf-8')
    
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            print(f"\n⏳ Connecting to {host}:{PORT}...")
            client_socket.connect((host, PORT))
            print(f"✓ Connected to server at {host}:{PORT}")
            
            print("\n" + "=" * 60)
            print("Communication established. You speak first.")
            print("Type 'exit' to end the conversation.")
            print("=" * 60 + "\n")
            
            while True:
                # Send message
                message = input("Your message: ")
                
                # Encrypt message
                message_bytes = message.encode('utf-8')
                encrypted_msg = des_encrypt(message_bytes, key_bytes)
                
                print(f"🔒 Sending (Encrypted): {encrypted_msg.hex().upper()}")
                
                # Send encrypted message
                client_socket.sendall(encrypted_msg)
                
                # Check if client wants to exit
                if message.lower() == 'exit':
                    print("✓ You ended the conversation.")
                    break
                
                print()
                
                # Receive reply
                print("⏳ Waiting for server's reply...")
                encrypted_data = client_socket.recv(4096)
                
                if not encrypted_data:
                    print("\n✗ Server disconnected.")
                    break
                
                # Display received ciphertext
                print(f"📩 Received (Encrypted): {encrypted_data.hex().upper()}")
                
                # Decrypt the message
                try:
                    decrypted_msg = des_decrypt(encrypted_data, key_bytes)
                    reply = decrypted_msg.decode('utf-8', errors='ignore')
                    print(f"🔓 Server's Reply: {reply}")
                except Exception as e:
                    print(f"❌ Decryption error: {e}")
                    continue
                
                # Check if server wants to exit
                if reply.lower() == 'exit':
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
