#!/usr/bin/env python3
"""
DES Encrypted Communication - Server
+ RSA key distribution
+ RSA digital signature (integrity + authentication)
"""

import socket
import hashlib
from des_crypto import des_encrypt, des_decrypt

HOST = "0.0.0.0"
PORT = 65432

# --- RSA SERVER PARAMETERS (demo) -------------------------------------------
RSA_P = 5666448961
RSA_Q = 5180577959
RSA_N = RSA_P * RSA_Q
RSA_PHI = (RSA_P - 1) * (RSA_Q - 1)
RSA_E = 65537

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

RSA_D = _modinv(RSA_E, RSA_PHI)

# --- Line helpers ------------------------------------------------------------
def send_line(conn, s: str):
    conn.sendall((s + "\n").encode("ascii"))

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
    # H(m) = SHA256(m) mod n  (biar muat ke modulus demo)
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % n

def rsa_sign(data: bytes, d: int, n: int) -> int:
    h = hash_to_int(data, n)
    return pow(h, d, n)

def rsa_verify(data: bytes, sig: int, e: int, n: int) -> bool:
    h = hash_to_int(data, n)
    v = pow(sig, e, n)
    return v == h

# --- RSA-based key distribution + signature ---------------------------------
def rsa_key_exchange_server(conn) -> bytes:
    """
    New:
    1) Server -> client : e_s, n_s
    2) Client -> server : e_c, n_c
    3) Client -> server : enc_des_int
    4) Client -> server : sig_int   (signature client atas enc_des_int)
    """
    print("🔐 Starting RSA key exchange (server)...")
    print(f"  Server public key: e = {RSA_E}, n = {RSA_N}")

    # 1) send server pubkey
    send_line(conn, str(RSA_E))
    send_line(conn, str(RSA_N))
    print("  → Sent RSA public key to client.")

    # 2) receive client pubkey
    client_e = int(recv_line(conn))
    client_n = int(recv_line(conn))
    print(f"  ← Received CLIENT public key: e = {client_e}, n = {client_n}")

    # 3) receive encrypted DES key (integer)
    enc_key_str = recv_line(conn)
    enc_des_int = int(enc_key_str)
    print(f"  ← Received encrypted DES key (integer): {enc_des_int}")

    # 4) receive signature
    sig_int = int(recv_line(conn))
    print("  ← Received signature for encrypted DES key.")

    # verify signature over ASCII of enc_des_int
    signed_bytes = enc_key_str.encode("ascii")
    if not rsa_verify(signed_bytes, sig_int, client_e, client_n):
        raise ValueError("Invalid signature on encrypted DES key (handshake)")

    print("  ✅ Signature valid. Proceeding decrypt...")

    # decrypt RSA -> DES key bytes
    shared_int = pow(enc_des_int, RSA_D, RSA_N)
    key_bytes = shared_int.to_bytes(8, byteorder="big")

    print(f"  🔑 Derived DES session key (hex): {key_bytes.hex().upper()}")
    print("✅ RSA key exchange DONE.\n")
    return key_bytes, (client_e, client_n)

def main():
    print("=" * 60)
    print("       DES ENCRYPTED COMMUNICATION - SERVER")
    print("=" * 60)
    print("RSA public-key distribution of DES secret key is ENABLED.")
    print("Digital signature is ENABLED (RSA textbook signature).\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)

        print(f"✓ Server is listening on {HOST}:{PORT}")
        print("⏳ Waiting for client connection...")

        conn, addr = server_socket.accept()
        with conn:
            print(f"✓ Client connected from {addr[0]}:{addr[1]}")

            try:
                key_bytes, (client_e, client_n) = rsa_key_exchange_server(conn)
            except Exception as e:
                print(f"❌ RSA key exchange failed: {e}")
                return

            print("\n" + "=" * 60)
            print("Communication established. Client will speak first.")
            print("Type 'exit' to end the conversation.")
            print("=" * 60 + "\n")

            while True:
                try:
                    print("⏳ Waiting for client's message...")
                    line = recv_line(conn)  # format: CIPHERHEX|SIGINT
                except Exception:
                    print("\n✗ Client disconnected.")
                    break

                if "|" not in line:
                    print("❌ Bad packet format (missing '|').")
                    continue

                cipher_hex, sig_str = line.split("|", 1)
                try:
                    encrypted_data = bytes.fromhex(cipher_hex)
                    sig_int = int(sig_str)
                except Exception:
                    print("❌ Bad packet values.")
                    continue

                # verify signature on ciphertext
                if not rsa_verify(encrypted_data, sig_int, client_e, client_n):
                    print("❌ Signature INVALID on message (tampered?). Ignored.")
                    continue

                print(f"📩 Received (Encrypted): {encrypted_data.hex().upper()}")
                try:
                    decrypted_msg = des_decrypt(encrypted_data, key_bytes)
                    message = decrypted_msg.decode("utf-8", errors="ignore")
                    print(f"🔓 Decrypted Message: {message}")
                except Exception as e:
                    print(f"❌ Decryption error: {e}")
                    continue

                if message.lower() == "exit":
                    print("✓ Client has ended the conversation.")
                    break

                print()
                reply = input("Your reply: ")

                reply_bytes = reply.encode("utf-8")
                encrypted_reply = des_encrypt(reply_bytes, key_bytes)

                # server signs its own ciphertext (client will verify pakai server (e,n) yg sudah dia terima)
                sig_reply = rsa_sign(encrypted_reply, RSA_D, RSA_N)

                print(f"🔒 Sending (Encrypted): {encrypted_reply.hex().upper()}")
                send_line(conn, f"{encrypted_reply.hex().upper()}|{sig_reply}")

                if reply.lower() == "exit":
                    print("✓ You ended the conversation.")
                    break

                print("-" * 60)

    print("\n" + "=" * 60)
    print("       Connection closed. Server shutting down.")
    print("=" * 60)

if __name__ == "__main__":
    main()
