from pwnlib.tubes.remote import remote
from Crypto.Util.number import long_to_bytes

BLOCK_SIZE = 16
HOST = "52.9.72.6"
PORT = 35198

def xor(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, b)])

with remote(HOST, PORT) as conn:
    line = conn.recvline(keepends=False)
    print(line)
    nonce = line[len("nonce: ") : ].decode()
    nonce = bytes.fromhex(nonce)

    line = conn.recvline(keepends=False)
    print(line)
    ciphertext = line[len("ciphertext: ") : ].decode()
    ciphertext = bytes.fromhex(ciphertext)

    print(conn.recvline())

    num_blocks = len(ciphertext) // BLOCK_SIZE
    print(f"num_blocks {num_blocks}")
    flag = ""
    num_requests = 0
    for block_idx in range(3, num_blocks):
        print(f"block_idx {block_idx}")

        cur_ciphertext_block = ciphertext[block_idx * BLOCK_SIZE : (block_idx + 1) * BLOCK_SIZE]
        plaintext_part = b"\x00" * (BLOCK_SIZE - 1)
        block_pad_part = xor(cur_ciphertext_block[ : BLOCK_SIZE - 1], plaintext_part)
        cur_counter = nonce + long_to_bytes(block_idx, 8)

        cur_block_pad = None
        for trial_block_pad_byte in range(256):
            if trial_block_pad_byte % 50 == 0:
                print(f"trial_block_pad_byte {trial_block_pad_byte}")

            trial_block_pad = block_pad_part + bytes([trial_block_pad_byte])
            trial_output = b"\x00" * 16 + trial_block_pad
            trial_output = trial_output.hex().encode()

            conn.sendline(trial_output)
            num_requests += 1
            res = conn.recvline(keepends=False).decode()
            res = bytes.fromhex(res)
            trial_counter = res[BLOCK_SIZE : BLOCK_SIZE * 2]

            if trial_counter == cur_counter:
                cur_block_pad = trial_block_pad
                break

        if cur_block_pad == None:
            print("Could not find block pad")
            exit()

        flag_char = cur_ciphertext_block[15] ^ cur_block_pad[15]
        flag_char = chr(flag_char)
        flag += flag_char
        print(f"found flag char {flag_char}")
    
    print(flag)
    print(f"num_requests {num_requests}")
