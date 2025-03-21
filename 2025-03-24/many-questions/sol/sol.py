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

def find_c1_byte(byte_pos: int, c1: bytearray, c2: bytes, conn: tube) -> int:
    """
    Finds the byte x in c1 at index byte_pos that makes the padding oracle report correct padding.

    c1 and c2 are AES ciphertext blocks sent as input. The input is constructed by concatentating
    c1 and c2 together.
    """

    for x in range(256):
        if x % 10 == 0:
            print(f"  x {x}")

        c1[byte_pos] = x
        inp = c1 + c2
        is_correct_padding = is_input_produce_correct_padding(inp, conn)
        if is_correct_padding:
            # Padding reported correct, ensure that padding is pad_value by changing byte at
            # (byte_pos - 1)

            # If byte_pos is 0, there is no need to check padding value, because there is only one
            # possible padding value in that case
            if byte_pos == 0:
                print(f"  x {x}")
                return x

            c1[byte_pos - 1] = 1
            inp = c1 + c2
            is_correct_padding = is_input_produce_correct_padding(inp, conn)
            c1[byte_pos - 1] = 0
            if is_correct_padding:
                print(f"  x {x}")
                return x

    # This should not happen, but helps with debugging the exploit script.
    print("  x not found")
    exit(1)



with process(["python", "chal.py"]) as conn:
#with remote(ADDRESS, PORT) as conn:
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

    num_blocks = len(ciphertext) // BLOCK_SIZE
    print(f"num_blocks {num_blocks}")

    # Decrypted ciphertext blocks, before XOR
    dec_cipher_blocks = bytearray(len(ciphertext))
    # Decrypted ciphertext blocks, after XOR
    plaintext = bytearray(len(ciphertext))
    # Appending IV to ciphertext makes decryption code a bit simpler
    ciphertext = iv + ciphertext

    for block_idx in range(num_blocks):
        print(f"block_idx {block_idx}")

        for byte_pos in range(BLOCK_SIZE - 1, -1, -1):
            # c_i: ciphertext block i in input
            # p_i: plaintext block i in output
            # Find byte x at byte_pos in c1 that results in correct padding in p2

            print(f"byte_pos {byte_pos}")

            pad_value = BLOCK_SIZE - byte_pos
            c1 = bytearray(BLOCK_SIZE)
            c2 = ciphertext[(block_idx + 1) * BLOCK_SIZE : (block_idx + 2) * BLOCK_SIZE]
            
            # Bytes in c1 from (byte_pos + 1) to (BLOCK_SIZE - 1) should make plaintext padding equal to
            # pad_value
            for i in range(byte_pos + 1, BLOCK_SIZE):
                c1[i] = dec_cipher_blocks[block_idx * BLOCK_SIZE + i] ^ pad_value

            x = find_c1_byte(byte_pos, c1, c2, conn)

            dec_cipher_block_byte = x ^ pad_value
            dec_cipher_blocks[block_idx * BLOCK_SIZE + byte_pos] = dec_cipher_block_byte
            # ciphertext includes IV block at start
            plaintext_byte = dec_cipher_block_byte ^ ciphertext[block_idx * BLOCK_SIZE + byte_pos]
            plaintext[block_idx * BLOCK_SIZE + byte_pos] = plaintext_byte
            print(f"  plaintext_byte {chr(plaintext_byte)}")

        print(f"plaintext {plaintext}")
