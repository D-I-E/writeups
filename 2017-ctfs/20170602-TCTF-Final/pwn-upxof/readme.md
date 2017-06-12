# upxof

This is quite an interesting challenge. I didn't solve it in the CTF since I know nothing about that ld trick.

But from this challenge, I learned a lot about ld trick, auxv etc.


# tl;dr
Abuse the auxv struct before uncompress process to bypass canary, and then ROP to run shellcode on rwx mappings mmaped by UPX uncompress process.

# Analysis

We are given a elf which can run directly, but asking us for password.

If you are in luck, you may find out that its password is actually 12345678, quite weak password.
You can analysis from IDA, with gdb tell you the start point as well. From a cmp assembly instruction, you can still get the password easily.

Well, if you have read the assembly code, you can also find out that the check is not so sufficient.
No length is checked. And the compare instruction makes the string truncated, so anything after that 12345678 password will not affect our result.

After that password, we get a chance to input any length string. To analysis this, you may just use upx to uncompress the elf. And, you'll see that this is from the uncompressed code, while the password thing is not.

So, we are getting clear. There is a vulnerability in the password input part and, of course the go part. But! The go part is from uncompressed code, and, it is canary-protected.

The question is that how can we bypass the canary?

# Where is canary born?

Now it is time to get some extra knowledge. Where is canary born? I mean, how is it initialized?

Well, it is actually generated from the linux kernel. But! It is transformed by some Auxiliary Vector!

Auxiliary Vector is at the top of the stack, it can be NULL actually, but if it is not NULL, you can get information from it.
And, the information is provided for the ld.so.

To see what auxv like, you can set the environment like this:
```shell
[anciety@anciety-pc upxof]$ LD_SHOW_AUXV=1 ./upxof_raw
password:12345678
AT_SYSINFO_EHDR: 0x7ffc17937000
AT_HWCAP:        bfebfbff
AT_PAGESZ:       4096
AT_CLKTCK:       100
AT_PHDR:         0x400040
AT_PHENT:        56
AT_PHNUM:        9
AT_BASE:         0x0
AT_FLAGS:        0x0
AT_ENTRY:        0x4005e0
AT_UID:          1000
AT_EUID:         1000
AT_GID:          1000
AT_EGID:         1000
AT_SECURE:       0
AT_RANDOM:       0x7ffc17855509
AT_EXECFN:       ./upxof_raw
AT_PLATFORM:     x86_64
let's go:
```

You can also use gdb to do this, just type `info auxv`, you will get similar input.

And the auxv struct is like this:
```c
typedef struct
{
        int a_type;                     /* Entry type */
        union
        {
                long int a_val;         /* Integer value */
                void *a_ptr;            /* Pointer value */
                void (*a_fcn) (void);   /* Function pointer value */
        } a_un;
} Elf32_auxv_t;
```
This is an entry struct. Take AT_HWCAP as example, the structure will be `p64(entry_type_no) + a_un`, where a_un is of 8 bytes long(under 64-bits).

Now we know about auxv, what else? Well, it seems that AT_RANDOM is an interesting variable that we should pay attention to.

This is something from the libc, and it does the stuff about canary. Actually, it sets the canary.

```c
static inline uintptr_t __attribute__ ((always_inline))
_dl_setup_stack_chk_guard (void *dl_random)
{
  union
  {
    uintptr_t num;
    unsigned char bytes[sizeof (uintptr_t)];
  } ret = { 0 };

  if (dl_random == NULL)
    {
      ret.bytes[sizeof (ret) - 1] = 255;
      ret.bytes[sizeof (ret) - 2] = '\n';
    }
  else
    {
      memcpy (ret.bytes, dl_random, sizeof (ret));
#if BYTE_ORDER == LITTLE_ENDIAN

      ret.num &= ~(uintptr_t) 0xff;
#elif BYTE_ORDER == BIG_ENDIAN

      ret.num &= ~((uintptr_t) 0xff << (8 * (sizeof (ret) - 1)));
#else

#error "BYTE_ORDER unknown"

#endif

    }
  return ret.num;
}
```

From this, we can see that the canary is set by dl_random. That is, if we are able to change the auxv struct before it is load, when it call ld, we can control the canary!

# Solve
1. Overflow into auxv, to control the canary before ld is called.
2. Bypass the canary, then we can do ROP.
3. Use ROP to call gets again, write shellcode into a rwx mapping. We have rwx mapping because the UPX needs it.
4. ROP jumps to the shellcode start point, and done.

# Notice
## To debug
The debug process is a little bit trickier than I ever thought. You can not just use `n` command to do everything, it may be broken! And step to the entry point of the uncompressed code is not so easy.
You need to do following steps:
1. run the binary, and let gdb attached to the running process(obviously)
2. now, before you continue, set a breakpoint at 0x400c93, and then, continue
3. do some 'n' command, until the instruction `call 0x800d14`
4. now, use 's' command to step in, then you will be at 0x800d14, set another breakpoint at 0x800d9d, continue.
5. use 's' command then, unless you are dealing with a call instruction, use 'n' command to step over that. DO NOT JUST USE N COMMAND! You will see how gdb tricks you if you do that.
6. now, use 's' command to step the instructions unless you are executing a call instruction. Do this until you get the address, 0x400604
7. Do the same, until you get some call rax, step into it(by using 's'), you will be at the entry of the uncompressed code.

This can be very annoying actually, I can't get a better solution since whenever I try to skip some part by using breakpoint and continue command, the gdb plays tricks with me, and I get confusing results.

## UPX, RWX and ROP
I don't know much about UPX, but during the debugging, I found that it actually did a lot things.
1. More mappings, some of them are RWX. In this challenge, at least 0x601000-0x602000 address is RWX, we can use that to write and execute shellcode.
2. The uncompress process is copied to 0x800000(as I remembered), and the original code, which is from 0x400000 will be the uncompressed code. So, to use ROP gadgets, you should find the gadgets inside the upx uncompressed binary. And you don't need to worry about the address since it adjusted the address it self.

## auxv
The auxv structure above is everything. The at_random address gdb tells you is found using that structure. So, you CANNOT just use the address of at_random `info auxv` to see if the at_random is modified. Actually, at_random's address is contained in that structure, it is like `p64(0x19) + p64(at_random_addr)`. To actually modify the at_random, the only thing you can do is to modify that address followed by the 0x19 number in the auxv. Changed it to point to some address which we already know the contents. (I used the address which is initiated to zero here)

# exp.py
see the exp.py in this directory

# References
1. http://phrack.org/issues/58/5.html 
2. https://www.elttam.com.au/blog/playing-with-canaries/
