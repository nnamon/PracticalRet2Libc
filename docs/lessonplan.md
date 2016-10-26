Syllabus
========

This presentation is designed to be a gentle introduction to return oriented
programming techniques in binary exploitation by demonstrating a subset of the
art called Return2Libc. Currently, the level of exploitation taught by the class
only includes the classic stack overflow and jump to shellcode with no
protections enabled. We wish to build upon this knowledge and introduce methods
to perform a successful attack when more protections are enabled (NX, Stack
Canaries, ASLR). As with the assignment 1 task, we will focus on 32 bit linux
binaries.

## Pre-Requisites

We assume participants have the following pre-requisites:

1. A thorough understanding of the classic buffer overflow techniques to spawn a
   shell (Assignment 1).
2. The ability to read C.
3. Some Python, GDB and bash knowledge.

Since time is rather limited, this will be a very fast paced lesson. Feel free
to pause the video or peruse the syllabus document for an in-depth explanation
for the concepts.

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
    char buffer[16];
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

Let us take a look at the memory mappings for such a binary.

```shell
gdb-peda$ vmmap
Start      End        Perm      Name
0x08048000 0x08049000 r-xp      /tmp/vuln1-nocanary-execstack
0x08049000 0x0804a000 r-xp      /tmp/vuln1-nocanary-execstack
0x0804a000 0x0804b000 rwxp      /tmp/vuln1-nocanary-execstack
0xf7df0000 0xf7df1000 rwxp      mapped
0xf7df1000 0xf7fa5000 r-xp      /lib/i386-linux-gnu/libc-2.21.so
0xf7fa5000 0xf7fa8000 r-xp      /lib/i386-linux-gnu/libc-2.21.so
0xf7fa8000 0xf7faa000 rwxp      /lib/i386-linux-gnu/libc-2.21.so
0xf7faa000 0xf7fac000 rwxp      mapped
0xf7fd5000 0xf7fd7000 rwxp      mapped
0xf7fd7000 0xf7fd9000 r--p      [vvar]
0xf7fd9000 0xf7fda000 r-xp      [vdso]
0xf7fda000 0xf7ffc000 r-xp      /lib/i386-linux-gnu/ld-2.21.so
0xf7ffc000 0xf7ffd000 r-xp      /lib/i386-linux-gnu/ld-2.21.so
0xf7ffd000 0xf7ffe000 rwxp      /lib/i386-linux-gnu/ld-2.21.so
0xfffdd000 0xffffe000 rwxp      [stack]
```

Important things to take note of the output above is the fact that the stack is
marked 'rwxp' which means it is both writable and executable.

## Exploitation Illustration

First, let's visualise how the stack looks like before the buffer is read into:

![Fig 1.1. Clean stack][classic1]

For clarification, the value of the saved base pointer is 0xbfff0030 and the
value of the return address is 0x080484f0 (an address within the binary). The
numbers are reversed in the visualisation because x86 is a little endian
architecture.

On a valid run of the program, the buffer is filled within its bounds. Here we
have 15 As and a null byte written to the 16 length buffer.

![Fig 1.2. Within the bounds][classic2]

However, since the read allows for the program to read more than 16 bytes into
the buffer, we can overflow it and overwrite the saved return pointer.

![Fig 1.3. Overwriting the saved return pointer][classic3]

When the function returns, the program will crash since the instruction pointer
is set to 0x41414141, an invalid address.

To complete the technique, the attacker will fill the first part of the buffer
with the shellcode, append the appropriate padding and overwrite the saved
return pointer with the address of the buffer.

[//]: # (![Fig 1.4. Shellcode and padding][classic4])

![Fig 1.5. Overwrite the saved return pointer with buffer address][classic5]

Now, when the function returns, the program will begin executing the shellcode
contained in the buffer since the saved return pointer was overwritten by the
buffer address (0xbfff0000). From this point onwards, the attacker has achieved
arbitrary code execution.

![Fig 1.6. Arbitrary code execution][classic6]


## ASLR, NX, Stack Canaries

Now that we understand how the classic exploitation technique works, let us
start introducing protections and observing how they prevent the technique from
working.

### No eXecute (NX)

Also known as Data Execution Prevention (DEP), this protection marks writable
regions of memory as non-executable. This prevents the processor from executing
in these marked regions of memory.

If we look at the memory map of

In the following diagrams, we will be introducing a new indicator colour for the
memory regions to denote 'writable and non-executable' mapped regions. Firstly,
the stack before the read occurs looks like this:

![Fig 2.1. Stack marked non-executable][nx1]

When we perform the same attack, the buffer is overrun and the saved pointers
are overwritten once again.

![Fig 2.2. Attack performed][nx2]

After the function returns, the program will set the instruction pointer to
0xbfff0000 and attempt to execute the instructions at that address. However,
since the region of memory mapped at that address has no execution permissions,
the program will crash.

![Fig 2.3. Non-executable memory violation][nx3]

Thus, the attacker's exploit is thwarted.

### Address Space Layout Randomisation

This protection randomises the addresses of the memory regions where the shared
libraries, stack, and heap are mapped at. The reason for this is to frustrate an
attacker since they cannot predict with certainty where their payload is located
at and the exploit will not work reliably.

On the first run of the program, the stack looks like this just before the read:

![Fig 3.1. Initial run 1][aslr1]

If we terminate the program and run it again, the stack might look like this
before the read:

![Fig 3.2. Initial run 2][aslr2]

Notice how the stack addresses do not stay constant and now have their base
values randomised. Now, the attacker attempts to re-use their payload from the
classic technique.

![Fig 3.3. Classic payload in ASLR][aslr3]

Notice that the saved return pointer is overwritten with a pointer into the
stack at an unknown location where the data is unknown and non-user controlled.
When the function returns, the program will begin executing unknown instructions
at that address (0xbfff0000) and will most likely crash.

![Fig 3.4. Executing in an unknown location][aslr4]

Thus, it is impossible for an attacker to be able to reliably trigger the
exploit using the standard payload.

### Stack Canaries

This protection places a randomised guard value after a stack frame's local
variables and before the saved return address. When a function returns, this
guard value is checked and if it differs from the value provided by a secure
source, then the program is terminated.

In the following stack diagram, an additional stack canary is added right after
the buffer. The valid value of this stack canary is 0x01efcdab.

![Fig 4.1. Stack canary after buffer][canary1]

Now, the attacker attempts their exploit with the standard payload again. The
stack diagram looks like this after the read:

![Fig 4.2. Stack canary corrupted][canary2]

Notice that the stack canary has been overwritten and corrupted by the padding
of 'A's (0x41). The value of the canary is now 0x41414141. Before the function
returns, the canary is xored against the value of the 'master' canary. If the
result is 0, implying equality, then the function is allowed to return.
Otherwise, the program terminates itself. In this case, the program fails the
check, prints a warning message, and exits.

![Fig 4.3. Stack canary check fails][canary3]

Thus, the attacker is not even able to redirect control flow and the exploit
fails.

## Return Oriented Programming

We will now introduce a technique to bypass the NX and ASLR protections.
Unfortunately, this technique does not work against stack canaries which require
an additional memory leak vulnerability or a precise write-what-where primitive
to bypass.

Return Oriented Programming is an exploitation technique to re-use executable
code portions in the binary or in other shared libraries. In this presentation,
we will not go too in-depth to the general ROP concepts and instead focus on a
subset called Return to Libc.

### Code Re-Use Example

To introduce the concept of re-using code within the binary, let us introduce an
extremely simple vulnerable binary that implements a password system.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void give_shell() {
    system("/bin/sh");
}

void vuln() {
    char password[16];
    puts("What is the password: ");
    scanf("%s", password);
    if (strcmp(password, "31337h4x") == 0) {
        puts("Correct password!");
        give_shell();
    }
    else {
        puts("Incorrect password!");
    }
}

int main() {
    vuln();
}
```

The assumptions we make are that the attacker does not know the password. They
have to exploit the program to obtain the shell. From this point onwards, we
assume that the NX and ASLR protections are enabled. Observing the output from
viewing the memory mapping permissions in GDB:

```shell
gdb-peda$ vmmap
Start      End        Perm      Name
0x08048000 0x08049000 r-xp      /tmp/vuln2
0x08049000 0x0804a000 r--p      /tmp/vuln2
0x0804a000 0x0804b000 rw-p      /tmp/vuln2
0xf7df0000 0xf7df1000 rw-p      mapped
0xf7df1000 0xf7fa5000 r-xp      /lib/i386-linux-gnu/libc-2.21.so
0xf7fa5000 0xf7fa8000 r--p      /lib/i386-linux-gnu/libc-2.21.so
0xf7fa8000 0xf7faa000 rw-p      /lib/i386-linux-gnu/libc-2.21.so
0xf7faa000 0xf7fac000 rw-p      mapped
0xf7fd5000 0xf7fd7000 rw-p      mapped
0xf7fd7000 0xf7fd9000 r--p      [vvar]
0xf7fd9000 0xf7fda000 r-xp      [vdso]
0xf7fda000 0xf7ffc000 r-xp      /lib/i386-linux-gnu/ld-2.21.so
0xf7ffc000 0xf7ffd000 r--p      /lib/i386-linux-gnu/ld-2.21.so
0xf7ffd000 0xf7ffe000 rw-p      /lib/i386-linux-gnu/ld-2.21.so
0xfffdd000 0xffffe000 rw-p      [stack]
```

Notice now that the stack is mapped 'rw-p'. Also, take note that ASLR is
enabled.

```shell
$ cat /proc/sys/kernel/randomize_va_space
2
```

#### Achieving EIP Control

The vulnerability lies in the line:

```c
    scanf("%s", password);
```

This string read is unbounded and will result in the password buffer being
overflown. We can achieve instruction pointer control by providing 28 bytes of
padding and then the overwrite value. To verify this:

```shell
$ python -c 'print "A"*28 + "BBBB"' | ./vuln2
What is the password:
Incorrect password!
Segmentation fault (core dumped)
$ dmesg | tail -f -n 1
[167511.081951] vuln2[32147]: segfault at 42424242 ip 0000000042424242 sp 00000000ffec80d0 error 14
```

#### Jump Where?

Now that we have EIP control, we need a target address to jump to. We cannot
re-use the idea of supplying shellcode in the buffer and then jumping there
because the NX protection prevents execution of the data and the ASLR protection
makes it very difficult for us to predict where the buffer is in the first
place.

However, recall that the binary provides a `give_shell()` function to supply a
shell. We may obtain the address of that function by using objdump.

```shell
$ objdump -d vuln2 | grep give_shell
080484cb <give_shell>:
 8048536:       e8 90 ff ff ff          call   80484cb <give_shell>
```

Since the 0x08048000 - 0x08049000 range of the binary is marked executable and
0x080484cb falls within them, this area of memory is a valid place for the
vulnerable function to return to and execute. Putting the exploit together:

```shell
$ (python -c 'import struct; print "A"*28 + struct.pack("I", 0x080484cb)'; cat -) | ./vuln2
What is the password:
Incorrect password!
id
uid=1000(amon) gid=1000(amon) groups=1000(amon)
```

### Function Re-Use Example

If you thought that the previous example seemed contrived, it is. Most programs
do not call system("/bin/sh") for you in such a convenient manner. We have
modified the program slightly to be a little more realistic.

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

char * not_allowed = "/bin/sh";

void give_date() {
    system("/bin/date");
}

void vuln() {
    char password[16];
    puts("What is the password: ");
    scanf("%s", password);
    if (strcmp(password, "31337h4x") == 0) {
        puts("Correct password!");
        give_date();
    }
    else {
        puts("Incorrect password!");
    }
}

int main() {
    vuln();
}
```

In this example, simply jumping to the `give_date()` function will not spawn a
shell but instead, print the date. This is not very useful to an attacker so we
need to look at some new techniques. At this point, we need to introduce 32 bit
calling conventions before proceeding.

#### Calling Conventions

To investigate how function calls work, we can take a look at what happens when
the `give_shell()` function is called. The function is called within the
`vuln()` function.

```shell
 8048536:   e8 90 ff ff ff          call   80484cb <give_date>
 804853b:  eb 10                   jmp    804854d <vuln+0x69>
```

To illustrate what is going on under the machinery, we re-introduce our stack
diagrams. Please note that the diagrams are a simplification and the values and
offsets do not accurately reflect an actual execution of the binary with regard
to space allocated for local variables and buffers. We begin at the address
0x08048536, just before the call to `give_date()` occurs.

![Fig 5.1. 0x08048536][callingconv1]

When the `give_date()` function is called, the following things happen:

1. The address of the next instruction in the `vuln()` function is pushed onto
   the stack (which means the stack pointer is decremented by 4). This value is
   0x0804853b.
2. The instruction pointer is set to the address of `give_date()`. This value is
   0x080484cb.

![Fig 5.2. 0x080484cb][callingconv2]

The disassembly of `give_date()` is as follows:

```shell
080484cb <give_date>:
 80484cb:       55                      push   %ebp
 80484cc:       89 e5                   mov    %esp,%ebp
 80484ce:       83 ec 08                sub    $0x4,%esp
 80484d4:       68 08 86 04 08          push   $0x8048608
 80484d9:       e8 b2 fe ff ff          call   8048390 <system@plt>
 80484de:       83 c4 10                add    $0x8,%esp
 80484e2:       c9                      leave
 80484e3:       c3                      ret
```

To annotate what's going on:

```shell
080484cb <give_date>:

== Function Prologue ==
 80484cb:       55                      push   %ebp
 80484cc:       89 e5                   mov    %esp,%ebp
 80484ce:       83 ec 08                sub    $0x4,%esp

== system("/bin/date") ==
 80484d4:       68 08 86 04 08          push   $0x8048608  ; "/bin/date"
 80484d9:       e8 b2 fe ff ff          call   8048390 <system@plt>

== Function Epilogue ==
 80484de:       83 c4 10                add    $0x8,%esp
 80484e2:       c9                      leave
 80484e3:       c3                      ret
```

Let us step through the function prologue to observe how a stack frame is
created. The first instruction, 0x080484cb is `push %ebp`. This pushes the base
pointer onto the stack. This will become the saved base pointer for stack frame.
The diagram shows the state of the registers and the stack after the instruction
has executed.

```shell
 80484cb:       55                      push   %ebp
```

![Fig 5.3. 0x080484cc][callingconv3]

The next instruction `mov %esp, %ebp` copies the value of the stack pointer into
the base pointer. This essentially sets the bottom of the current stack frame to
the top of the previous stack frame.

```shell
 80484cc:       89 e5                   mov    %esp,%ebp
```

![Fig 5.4. 0x080484ce][callingconv4]

The next instruction `sub $0x4, %esp` subtracts 4 from the current stack pointer
to allocate space for the local variables.

```shell
 80484ce:       83 ec 08                sub    $0x4,%esp
```

![Fig 5.5. 0x080484d4][callingconv5]

The next instruction `push $0x08048608` pushes the address of the string
"/bin/date" on the stack. Note that the parameters to the called function are
pushed in reverse order.

```shell
 80484d4:       68 08 86 04 08          push   $0x8048608  ; "/bin/date"
```

![Fig 5.6. 0x080484d9][callingconv6]

Next, when the `call 0x08048390` instruction executes, two things happen:

1. The next instruction in the `give_date()` function, 0x080484de, is pushed
   onto the stack as the saved return pointer.
1. The instruction pointer is set to address of `system@plt`, 0x08048390.

```shell
 80484d9:       e8 b2 fe ff ff          call   8048390 <system@plt>
```

![Fig 5.7. 0x08048390][callingconv7]

We will not go into the details of the system@plt call. However, during the
execution of the call, the stack frames look like this:

![Fig 5.8. During system@plt][callingconv8]

After the system@plt call returns, the stack diagram looks like the following:

![Fig 5.9. After system@plt][callingconv9]

Now, we can begin examining how the function unwinds the stack frame in the
epilogue. In the next instruction `add $0x8, %esp`, the 8 is added to the stack
pointer to reverse the allocation on the stack for the local variables and the
parameters of the system@plt call.

```shell
 80484de:       83 c4 10                add    $0x8,%esp
```

![Fig 5.10. 0x080484e2][callingconv10]

Next, let us look at the `leave` instruction. This simple opcode does two
things:

1. Sets the value of the stack pointer to the value of the base pointer.
2. Pops a value off the stack into the base pointer.

This has the effect of resetting the current stack frame back to the previous
stack frame.

```shell
 80484e2:       c9                      leave
```

![Fig 5.11. 0x080484e3][callingconv11]

Finally, to return execution back to the `vuln()` function context, the `ret`
instruction pops a value of the stack (the saved return pointer) into the
instruction pointer register.

```shell
 80484e3:       c3                      ret
```

![Fig 5.12. 0x0804853b][callingconv12]

In summary, we have observed how two stack frames were constructed and torn
down, the `give_date()` stack frame which has no parameters and the `system@plt`
stack frame which took one parameter.

#### Faking Stack Frames

Implicitly, we have also illustrated that stack frames control how the program
unwinds when returning from a function. Now, if we could construct and fake our
own stack frames during the attack, the implications are:

1. We can control the parameters to a function (f1) we jump to.
2. When f1 completes execution and returns, we can decide where it returns to
   (f2).
3. If we can manipulate the stack in between f1 returning into f2, we can
   control the parameters to the f2.
4. We can repeat this process to arbitrarily construct a 'chain' of functions to
   execute to perform effect we want.

To begin with, let us demonstrate faking a stack frame for a single function,
`system@plt` with our own chosen parameter "/bin/sh" to spawn a shell.

Before the read, the region after the saved return pointer for the `vuln()`
function looks like this. 0x08048566 is the legitimate address into `main()`
that `vuln()` will return to.

![Fig 6.1. Before read][faking1]

Before continuing the attacker requires a couple of values to construct the
payload. We need the following things:

1. Address to jump to. We shall use 0x08048390. This is the address of
   `system@plt`.
2. Address of "/bin/sh" to provide as a parameter. Conveniently, there is a
   "/bin/sh" string already present in the binary in the `not_allowed` global
   variable. It's address is 0x8048600.

After the attacker supplies their special payload to overwrite the saved return
pointer and fake a frame, the stack now looks like this:

![Fig 6.2. After read][faking2]

In the scenario, f1 is `system@plt`. In `vuln()`'s stack frame, the saved return
pointer is overwritten with the address of f1 (`system@plt`) which means that
when `vuln()` returns, it will jump to f1. Additionally, a new stack frame for
f1 is created which includes a saved return pointer and a parameter.

Let us step through what happens when `vuln()` returns. At the point where the
`ret` is about to be executed, the stack pointer points at the saved return
pointer to be popped into the instruction pointer.

![Fig 6.3. Before ret][faking3]

When the `ret` executes, the stack pointer will be decremented by 4 and the
instruction pointer will now contain the address of f1 (`system@plt`). At this
point, f1 will view the current stack frame as a valid one containing "/bin/sh"
as a parameter and 0x41414141 as the saved return address. During f1's
execution, a shell should be spawned. Now, let us assume that f1 has completed
execution and is now about to perform its own `ret`. It will pop the value of
0x41414141 off the stack into EIP and crash since the instruction pointer is now
attempting to execute at an illegal address.

![Fig 6.4 After f1][faking4]

However, imagine if 0x41414141 was a valid address. We would have been able to
keep chaining `ret` instructions to continuously execute other functions as long
as they do not need parameters passed to them.

#### Exploit Demonstration

Now that we have got the theory down, we should be able to spawn a shell of our
own.

```shell
$ (python -c 'import struct; \
> v_ret=0x08048390;
> f1_ret=0x41414141;
> f1_param=0x8048600;
> print "A"*28 + struct.pack("III", v_ret, f1_ret, f1_param)';
> cat -) | ./vuln3
What is the password:
Incorrect password!
id
uid=1000(amon) gid=1000(amon) groups=1000(amon)
exit
Segmentation fault (core dumped)
```

#### Pop Pop Ret

[//]: # (Paths)
[classic1]: ./diagrams/classic1.png
[classic2]: ./diagrams/classic2.png
[classic3]: ./diagrams/classic3.png
[classic4]: ./diagrams/classic4.png
[classic5]: ./diagrams/classic5.png
[classic6]: ./diagrams/classic6.png
[nx1]: ./diagrams/nx1.png
[nx2]: ./diagrams/nx2.png
[nx3]: ./diagrams/nx3.png
[aslr1]: ./diagrams/aslr1.png
[aslr2]: ./diagrams/aslr2.png
[aslr3]: ./diagrams/aslr3.png
[aslr4]: ./diagrams/aslr4.png
[canary1]: ./diagrams/canary1.png
[canary2]: ./diagrams/canary2.png
[canary3]: ./diagrams/canary3.png
[callingconv1]: ./diagrams/callingconv1.png
[callingconv2]: ./diagrams/callingconv2.png
[callingconv3]: ./diagrams/callingconv3.png
[callingconv4]: ./diagrams/callingconv4.png
[callingconv5]: ./diagrams/callingconv5.png
[callingconv6]: ./diagrams/callingconv6.png
[callingconv7]: ./diagrams/callingconv7.png
[callingconv8]: ./diagrams/callingconv8.png
[callingconv9]: ./diagrams/callingconv9.png
[callingconv10]: ./diagrams/callingconv10.png
[callingconv11]: ./diagrams/callingconv11.png
[callingconv12]: ./diagrams/callingconv12.png
[faking1]: ./diagrams/faking1.png
[faking2]: ./diagrams/faking2.png
[faking3]: ./diagrams/faking3.png
[faking4]: ./diagrams/faking4.png


