# chal1 | Binary Exploitation | UtahSec 2024-11-14

## Initial analysis

We are given binary files `chal1`, `libc.so.6,` and `ld-linux-x86-64.so.2`.
* `chal1` is the vulnerable binary running on the server at the given IP address and port number.
* `libc.so.6` is the C standard library used by `chal1`.
* `ld-linux-x86-64.so.2` is the dynamic linker for the specific version of the given libc binary.

For fun, you can run the libc binary with the ld-linux.so linker to see the libc version.
```
./ld-linux-x86-64.so.2 ./libc.so.6
```

Let's inspect the binary.
```
$ file chal1
chal1: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ld-linux-x86-64.so.2, BuildID[sha1]=82206e976c7e070c37c58300a612ef3b77864a43, for GNU/Linux 4.4.0, not stripped
```

The binary is not stripped, meaning that symbol names (for functions and global variables) are intact, which makes reversing this binary easier.

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

Let's also look at the decompilation of some of the functions using Ghidra.
```
 1      void disable_buffers(void)
 2      {
 3        setbuf(stdin,(char *)0x0);
 4        setbuf(stdout,(char *)0x0);
 5        setbuf(stderr,(char *)0x0);
 6        return;
 7      }
 8      
 9      undefined8 main(void)
10      {
11        char local_98 [0x40];
12        char local_58 [0x48];
13        uint local_10;
14        int local_c;
15        
16        disable_buffers();
17        puts("What is your name?");
18        fgets(name,0x40,stdin);
19        puts("What starting index for a name substring do you want?");
20        __isoc99_scanf(&DAT_00102056,&local_c);
21        getchar();
22        puts("What substring length do you want?");
23        __isoc99_scanf(&DAT_00102083,&local_10);
24        getchar();
25        strncpy(local_58,name + local_c,(ulong)local_10);
26        local_58[local_10] = '\0';
27        puts("Here is your substring:");
28        puts(local_58);
29        puts("What\'s a fun fact about yourself?");
30        gets(local_98);
31        puts("See you soon!");
32        return 0x0;
33      }
```

We can ignore the `disable_buffers` function. Disabling the standard IO streams is very common in CTF pwn challenges. What is very interesting is the use of `gets` on line 30, which makes `main` vulnerable, because `gets` writes to a buffer without checking the bound of the buffer. `local_98` is a stack buffer, so we can use `gets` to achieve a stack buffer overflow and overwrite the return address of `main`.

A stack buffer overflow is often used for ROP (return oriented programming), especially when the stack is non-executable, which is true in our case since the `checksec` command indicated that NX is enabled. To use ROP to open a shell, which is our goal, we can call the `system` function in libc with the argument `/bin/sh`. Therefore, we want to know the address of `system` in the process virtual memory, which will be randomized because of ASLR.
