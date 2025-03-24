# many-questions | Cryptography | UtahSec 2024-03-24
Author: Carson He

`nc 54.68.96.131 51478`

## Introduction

The goal of this workshop is to solve the many-questions challenge and get the flag.

A template solution script is provided at `sol-template.py`. Ensure that the `pwntools` Python package is installed. When running the challenge server locally, make sure to make a `flag.txt` file with a fake flag. For exploit development, it is recommended for the fake flag to have over 16 characters.

The full solution is a bit complex, so the following tasks break down the challenge into parts. Each task has spoilers for the solution.

## Task 1

The challenge has a padding oracle. In the `decrypt` function, the `unpad` function will throw an exception if the decrypted data has invalid padding, according to the PyCryptodome documentation (https://www.pycryptodome.org/src/util/util#Crypto.Util.Padding.unpad). We also see from the documentation that the padding scheme used by the challenge is PKCS#7. Search the web for the format of PKCS#7 padding, which is a fairly simple format.

Our goal is to decrypt the flag, but the only information that the server will give is whether the decryption was successful or not.

**Task**: Use the padding oracle to decrypt one byte in some position of the flag.

<details>
<summary>Solution hint</summary>
Brute force search for the last byte of the first block of the flag.
</details>

## Task 2

**Task**: Extend the solution for Task 1 to decrypt all bytes of only a single block of the flag.

<details>
<summary>Solution hint</summary>
Use the Task 1 solution to find the bytes within the first block in reverse order. On each iteration, ensure that the last part of the plaintext block contains the correct padding value.
</details>

## Task 3

**Task**: Extend the solution for Task 2 to decrypt all blocks of the flag.
