from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)
iv = get_random_bytes(16)

with open("flag.txt", "r") as file:
    flag = file.read()
flag = flag.strip().encode()



def encrypt(plaintext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    plaintext = pad(plaintext, AES.block_size)
    res = cipher.encrypt(plaintext)
    return res

def decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    res = cipher.decrypt(ciphertext)
    res = unpad(res, AES.block_size)
    return res



print("SECRET ANNOUNCEMENT:")
enc_flag = encrypt(flag, key, iv)
print(enc_flag.hex())
print("IV:")
print(iv.hex())

print()
print("Please ask any questions that you have.")
print("All questions must be encrypted for security and formatted in hex.")
print("Enter \"exit\" to exit.")

while True:
    inp = input("> ")

    if inp == "exit":
        break

    try:
        inp = bytes.fromhex(inp)
    except Exception:
        print("Input is not properly formatted in hex.")
        continue
        
    try:
        question = decrypt(inp, key, iv)
    except Exception as e:
        print("Decryption error.")
        continue

    print("Thank you for your question. I will make sure to respond as soon as I possibly can.")
    # Haha no one cares
    del question
