from pwn import * # type: ignore

ADDRESS = ""
PORT = 51478

BLOCK_SIZE = 16

def is_input_produce_correct_padding(inp: bytes | bytearray, conn: tube) -> bool:
    """
    Sends inp to the server and returns whether the server reports that the decrypted inp has
    correct padding or not.
    """

    inp_hex = inp.hex().encode()
    conn.recvuntil(b"> ")
    conn.sendline(inp_hex)
    line = conn.recvline(keepends=False)
    return b"Thank" in line



# Test exploit against local challenge process
conn = process(["python", "chal.py"])
# Run exploit against remote challenge server to get the true flag
#conn = remote(ADDRESS, PORT)

with conn:
    # SECRET ANNOUNCEMENT:
    print(conn.recvline())
    line = conn.recvline(keepends=False)
    print(line)
    ciphertext = bytes.fromhex(line.decode())
    # IV:
    print(conn.recvline())
    line = conn.recvline(keepends=False)
    print(line)
    iv = bytes.fromhex(line.decode())

    print(conn.recvline())
    # Please ask any questions that you have.
    print(conn.recvline())
    # All questions must be encrypted for security and formatted in hex.
    print(conn.recvline())
    # Enter "exit" to exit.
    print(conn.recvline())

    # --- Your code here ---

    c1 = bytearray(BLOCK_SIZE)
    c2 = ciphertext[:BLOCK_SIZE]

    x = 0
    is_x_found = False
    for x in range(256):
        if x % 10 == 0:
            print(f"x {x}")

        # p2 = AES_decrypt(c2, k) XOR c1
        # Check whether p2 has correct padding. If padding is correct, pad value in p2 is likely 0x1.
        c1[15] = x
        inp = c1 + c2
        is_padding_correct = is_input_produce_correct_padding(inp, conn)

        if is_padding_correct:
            is_x_found = True
            print(f"found x {x}")
            # Optionally, ensure that pad value is 0x1 by sending another query with a different byte
            # in c1 at index 14, but the chances of a different pad value are very small.
            break

    if not is_x_found:
        print("x not found")
        exit(1)

    dec_cipher_block_byte = x ^ 0x1
    plaintext_byte = dec_cipher_block_byte ^ iv[15]
    print(f"plaintext_byte {chr(plaintext_byte)}")
