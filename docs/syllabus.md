Presentation and Tutorial Concept
=================================

This presentation is designed to be a gentle introduction to return oriented
programming techniques in binary exploitation by demonstrating a subset of the
art called Return2Libc. Currently, the level of exploitation taught by the class
only includes the classic stack overflow and jump to shellcode with no
protections enabled. We wish to build upon this knowledge and introduce methods
to perform a successful attack when more protections are enabled (NX, Stack
Canaries, ASLR).

## Basic Exploitation Refresher

Recall the vulnerable binary that was presented in the first assignment. The
vulnerable portion of the code is as follows:

```c
#define BUFSIZE 64

int idx  = 0;
int idx1 = 0;
int idx2 = 0;
size_t byte_read1 = 0;
size_t byte_read2 = 0;
char buf1[BUFSIZE + 1];
char buf2[BUFSIZE + 1];

void bof(FILE * fd1, FILE * fd2)
{
    int i, j;
    char buf[BUFSIZE];
    i = j = 1;

    byte_read1 = fread(buf1, 1, BUFSIZE, fd1);
    byte_read2 = fread(buf2, 1, BUFSIZE, fd2);
    buf1[BUFSIZE] = '\0';
    buf2[BUFSIZE] = '\0';

    if(byte_read1 != byte_read2)
    {
        printf("Reading different number of bytes from ./exploit1 and ./exploit2!\n");
        return;
    }

    for(idx = 0; idx < byte_read1 + byte_read2; idx++)
    {
        idx1 = (idx % 2) ? BUFSIZE : idx / 2;
        idx2 = (idx % 2) ? (idx - 1) / 2: BUFSIZE;

        buf[idx] = buf1[idx1] + buf2[idx2];
    }

    printf("i = 0x%x, j = 0x%x\n", i, j);
}
```

The binary is compiled and the environment is setup as follows:

```shell
gcc -o buffer-overflow buffer-overflow.c -g –fno-stack-protector
sudo execstack –s buffer-overflow
echo 0 | sudo tee /sys/proc/kernel/randomize_va_space
```

In summary, the binary is vulnerable to a standard stack overflow and all
protections are turned off. In particular, the stack and heap are executable,
address space layout randomisation is turned off, and stack canaries are not
compiled into the binary. This means that the classic technique of placing
shellcode on the stack, overwriting the saved returned address with the address
of the shellcode, and jumping to it will work.

## Sample Vulnerable Code

To simplify exploring the concepts, we will not adhere strictly to the details
of the vulnerable code in the assignment. We will consider a cliché
implementation of a vulnerable program:

```c
#include <unistd.h>
#include <stdio.h>

void vuln() {
    char buffer[24];
    read(0, buffer, 100);
    puts(buffer);
}

int main() {
    vuln();
}
```

We will start without any protections at all:

```shell
gcc -m32 -o vuln1-nocanary-execstack -fno-stack-protector -zexecstack vuln1.c
echo 0 | sudo tee /sys/proc/kernel/randomize_va_space
```

Breaking down the important arguments and commands:

`gcc -m32 -o vuln1-nocanary-execstack -fno-stack-protector -zexecstack vuln1.c`
* -m32: Compile as a 32 bit application
* -fno-stack-protector: Disable the stack canary protection
* -zexecstack: Mark the stack and heap memory regions as executable

`echo 0 | sudo tee /sys/proc/kernel/randomize_va_space`
* Write 0 into the randomize\_va\_space kernel parameter to disable ASLR.

## Exploitation Illustration

## ASLR, NX, Stack Canaries

Now that we understand how the classic exploitation technique works, let us
start introducing protections and observing how they prevent the technique from
working.

### No eXecute (NX)

Also known as Data Execution Prevention (DEP), this protection marks writable
regions of memory as non-executable. This prevents the processor from executing
in these marked regions of memory.

### Address Space Layout Randomisation

This protection randomises the addresses of the memory regions where the shared
libraries, stack, and heap are mapped at. The reason for this is to frustrate an
attacker since they cannot predict with certainty where their payload is located
at and the exploit will not work reliably.

### Stack Canaries

This protection places a randomised guard value after a stack frame's local
variables and before the saved return address. When a function returns, this
guard value is checked and if it differs from the value provided by a secure
source, then the program is terminated.

## Return Oriented Programming

We will now introduce a technique to bypass the NX and ASLR protections.
Unfortunately, this technique does not work against stack canaries which require
an additional memory leak vulnerability or a precise write-what-where primitive
to bypass.

Return Oriented Programming is an exploitation technique to re-use executable
code portions in the binary or in other shared libraries. In this presentation,
we will not go too in-depth to the general ROP concepts and instead focus on a
subset called Return to Libc.
