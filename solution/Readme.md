# Solution to `Author's Demise`

The binary needs to be reverse engineered to identify the vulnerability. Tools like Ghidra, IDA Pro, or binary analysis can be used.

## Vulnerability Analysis
The `create_chapter()` function allocates a struct on the heap:
```c
typedef struct {
    char name[16];
    char content[16];
    void (*print_func)(void *);
} chapter;
```

The vulnerability exists when reading chapter content - the `gets()` function allows writing beyond the 16-byte `content` buffer, overwriting the `print_func` pointer at offset 0x20.

## Exploitation Steps
1. Identify the `give_flag()` function address using the binary's symbol table
2. Create a chapter with normal name input
3. Overflow the `content` buffer with 16 bytes of padding
4. Overwrite the `print_func` pointer with the address of `give_flag()`
5. Publish the book to trigger the hijacked function pointer
6. Capture the flag when `give_flag()` executes

## Solution Script
A Python script `exploit.py` is provided using pwntools to automate the exploitation:
- Extracts the `give_flag` address from the ELF binary
- Crafts a 24-byte payload (16 bytes padding + 8 bytes function pointer)
- Sends the payload to overflow the heap buffer
- Triggers execution by publishing the book

Flag: `LNMHACKS{h34p_func710n_p01n73r_h1j4ck}`