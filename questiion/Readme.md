# Author's Demise, 200 points
## Author: [KavyaTejpal](https://github.com/KavyaTejpal)
## Problem
A mysterious book publishing application allows you to create chapters and publish your masterpiece. However, the author's fate is sealed in the code - can you exploit the memory corruption vulnerability to reveal what happened to them?

A binary executable `vuln` is given.

## Producing it
Use `vuln.c` to compile the vulnerable binary:
```bash
gcc vuln.c -o vuln -no-pie -fno-stack-protector -z execstack
```

The binary is compiled with:
- No PIE (Position Independent Executable) - makes addresses predictable
- No stack protector - disables stack canaries
- Executable stack - allows code execution from stack (though not needed for this exploit)

The vulnerability lies in the heap-allocated `chapter` structure where a buffer overflow in the `content` field can overwrite the adjacent `print_func` function pointer, allowing control flow hijacking to execute the `give_flag()` function.