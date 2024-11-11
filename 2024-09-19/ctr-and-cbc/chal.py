from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from socketserver import ThreadingTCPServer, StreamRequestHandler
from argparse import ArgumentParser
import os

REQUEST_LIMIT = 30_000
SUBPROCESS_TIMEOUT = 60 * 60 # 1 hour

with open("flag.txt", "rb") as flag_file:
    flag = flag_file.read()
flag = flag.strip()
message = \
    b"AES is unbreakable! My secret is safe:" + b"\xff" * 10
for c in flag:
    message += b"\x00" * 15 + bytes([c])

class ChalTCPHandler(StreamRequestHandler):
    def handle(self):
        # Send encrypted message
        key = get_random_bytes(32)
        nonce = get_random_bytes(8)
        ctr_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = ctr_cipher.encrypt(message)
        print(f"nonce: {nonce.hex()}")
        print(f"ciphertext: {ciphertext.hex()}")

        # Decrypt input ciphertexts
        print("Send blank line to quit")
        iv = get_random_bytes(16)
        num_requests = 0
        while num_requests < REQUEST_LIMIT:
            try:
                request_ciphertext = input()
                if request_ciphertext == "":
                    break
                num_requests += 1
                request_ciphertext = bytes.fromhex(request_ciphertext)

                cbc_cipher = AES.new(key, AES.MODE_CBC, iv=iv)
                request_plaintext = cbc_cipher.decrypt(request_ciphertext)
                print(request_plaintext.hex())
            except ValueError:
                print("Error")
                continue
            except EOFError:
                exit()
