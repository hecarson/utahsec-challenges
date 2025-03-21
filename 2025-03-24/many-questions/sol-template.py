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


