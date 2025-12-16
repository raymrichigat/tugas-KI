#!/usr/bin/env python3
"""
DES Encrypted Communication - Client
+ RSA key distribution
+ RSA digital signature (integrity + authentication)
"""

import socket
import secrets
import hashlib
from des_crypto import des_encrypt, des_decrypt

PORT = 65432

# --- CLIENT RSA PARAMETERS (demo) -------------------------------------------
# (primes demo; beda dari server)
CLIENT_RSA_P = 6763000001
CLIENT_RSA_Q = 7129000001
CLIENT_RSA_N = CLIENT_RSA_P * CLIENT_RSA_Q
CLIENT_RSA_PHI = (CLIENT_RSA_P - 1) * (CLIENT_RSA_Q - 1)
CLIENT_RSA_E = 65537

def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x1, y1 = _egcd(b, a % b)
    return g, y1, x1 - (a // b) * y1

def _modinv(a, m):
    g, x, _ = _egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse for RSA_E modulo phi(N)")
    return x % m

CLIENT_RSA_D = _modinv(CLIENT_RSA_E, CLIENT_RSA_PHI)

# --- Line helpers ------------------------------------------------------------
def send_line(sock, s: str):
    sock.sendall((s + "\n").encode("ascii"))

# Simpan sisa data per-socket (biar 1 recv_line() cuma ambil 1 baris)
_socket_buffers = {}

def recv_line(sock) -> str:
    buf = _socket_buffers.get(sock, b"")

    # Pastikan buffer berisi minimal 1 newline
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed while waiting for line")
        buf += chunk

    # Ambil 1 baris pertama, simpan sisanya buat pemanggilan berikutnya
    line, rest = buf.split(b"\n", 1)
    _socket_buffers[sock] = rest

    return line.decode("ascii").strip()

def send_line(sock, s: str):
    sock.sendall((s + "\n").encode("ascii"))

# --- RSA signature helpers ---------------------------------------------------
def hash_to_int(data: bytes, n: int) -> int:
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % n

def rsa_sign(data: bytes, d: int, n: int) -> int:
    h = hash_to_int(data, n)
    return pow(h, d, n)

def rsa_verify(data: bytes, sig: int, e: int, n: int) -> bool:
    h = hash_to_int(data, n)
    v = pow(sig, e, n)
    return v == h

# --- RSA key distribution (client side) + signature --------------------------
def rsa_key_exchange_client(client_socket):
    """
    New:
    1) Receive server public key (e_s, n_s)
    2) Send client public key (e_c, n_c)
    3) Generate DES key (8 bytes)
    4) Encrypt DES key with server pub -> enc_des_int
    5) Sign enc_des_int using client private key -> sig_int
    6) Send enc_des_int + sig_int
    """
    print("🔐 Starting RSA key exchange (client)...")

    # 1) receive server pubkey
    e_s = int(recv_line(client_socket))
    n_s = int(recv_line(client_socket))
    print(f"  ← Received SERVER public key: e = {e_s}, n = {n_s}")

    # 2) send client pubkey
    send_line(client_socket, str(CLIENT_RSA_E))
    send_line(client_socket, str(CLIENT_RSA_N))
    print(f"  → Sent CLIENT public key: e = {CLIENT_RSA_E}, n = {CLIENT_RSA_N}")

    # 3) generate DES key
    key_bytes = secrets.token_bytes(8)
    print(f"  🔑 Generated DES session key (hex): {key_bytes.hex().upper()}")

    # 4) RSA encrypt DES key with server pubkey
    m = int.from_bytes(key_bytes, byteorder="big")
    enc_des_int = pow(m, e_s, n_s)

    # 5) sign the ASCII of enc_des_int using client privkey
    enc_str = str(enc_des_int)
    sig_int = rsa_sign(enc_str.encode("ascii"), CLIENT_RSA_D, CLIENT_RSA_N)

    # 6) send enc_des_int and sig_int
    send_line(client_socket, enc_str)
    send_line(client_socket, str(sig_int))
    print(f"  → Sent encrypted DES key (integer): {enc_des_int}")
    print("  → Sent signature for encrypted DES key.")
    print("✅ RSA key exchange DONE.\n")

    return key_bytes, (e_s, n_s)

def main():
    print("=" * 60)
    print("       DES ENCRYPTED COMMUNICATION - CLIENT")
    print("=" * 60)

    host = input("Enter server IP address [localhost]: ").strip() or "localhost"

    print("RSA public-key distribution of DES secret key is ENABLED.")
    print("Digital signature is ENABLED (RSA textbook signature).")
    print("Both parties do NOT know the DES key beforehand.\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
        try:
            print(f"⏳ Connecting to {host}:{PORT}...")
            client_socket.connect((host, PORT))
            print(f"✓ Connected to server at {host}:{PORT}")

            # Handshake
            key_bytes, (server_e, server_n) = rsa_key_exchange_client(client_socket)

            print("\n" + "=" * 60)
            print("Communication established. You speak first.")
            print("Type 'exit' to end the conversation.")
            print("=" * 60 + "\n")

            while True:
                message = input("Your message: ")
                message_bytes = message.encode("utf-8")
                encrypted_msg = des_encrypt(message_bytes, key_bytes)

                # client signs its ciphertext
                sig_int = rsa_sign(encrypted_msg, CLIENT_RSA_D, CLIENT_RSA_N)

                print(f"🔒 Sending (Encrypted): {encrypted_msg.hex().upper()}")
                send_line(client_socket, f"{encrypted_msg.hex().upper()}|{sig_int}")

                if message.lower() == "exit":
                    print("✓ You ended the conversation.")
                    break

                print("\n⏳ Waiting for server's reply...")
                line = recv_line(client_socket)  # format: CIPHERHEX|SIGINT

                if "|" not in line:
                    print("❌ Bad packet format from server.")
                    continue

                cipher_hex, sig_str = line.split("|", 1)
                try:
                    encrypted_data = bytes.fromhex(cipher_hex)
                    sig_srv = int(sig_str)
                except Exception:
                    print("❌ Bad packet values from server.")
                    continue

                # verify server signature using server public key
                if not rsa_verify(encrypted_data, sig_srv, server_e, server_n):
                    print("❌ Signature INVALID on server reply (tampered?). Ignored.")
                    continue

                print(f"📩 Received (Encrypted): {encrypted_data.hex().upper()}")

                try:
                    decrypted_msg = des_decrypt(encrypted_data, key_bytes)
                    reply = decrypted_msg.decode("utf-8", errors="ignore")
                    print(f"🔓 Server's Reply: {reply}")
                except Exception as e:
                    print(f"❌ Decryption error: {e}")
                    continue

                if reply.lower() == "exit":
                    print("✓ Server has ended the conversation.")
                    break

                print("-" * 60)

        except ConnectionRefusedError:
            print(f"❌ Could not connect to server at {host}:{PORT}")
        except KeyboardInterrupt:
            print("\n✗ Client interrupted by user.")
        except Exception as e:
            print(f"❌ Error: {e}")

    print("\n" + "=" * 60)
    print("       Connection closed.")
    print("=" * 60)

if __name__ == "__main__":
    main()
