# world of fastbin

This is a quite simple challenge, and there is so many ways to solve it. I present what I used during the competiton here.

# Analysis
Quite a simple binary, the vulnerability is very simple to find. The fill function has not checked the length. So you can actually input string of any length which will cause heap overflow.

But if you do checksec the binary, you'll understand when the challenge becomes hard.
We have almost all the protection here.

# Solution
## leak the heap
We have PIE and ASLR here, we need to get some address so we can get further.

To leak the heap address, since the malloc length is set to at most 0x5f(which is 0x60 internally), we almost always use the fastbin. Well, almost, we'll see that later. When we free 2 fastbins, the second one's FD will points to the first one. That is great, since that is a heap address. But to read that, we need to use the fill function to overflow something.

We use the fill to overflow the size of the next chunk, so, when free, we get a chunk bigger than its recorded size. That will give us an overlap, which may contain the next chunk. Then let the next chunk be the second fastbin chunk to be freed, we get the heap address.

## leak the libc address
libc address is almost the same. Get some overlap, and read the freed chunk. The difference is that we have to free some small bin. Since small bin is a double-linked list, when it is empty, we'll get a freed chunk whose FD and BK point to some address in main_arena, which is a global variable in libc.Then we can get the libc address. To get the offset, I recommand the [script](https://github.com/Escapingbug/get_main_arena) written by me to get main_arena offset from any libc.

## control flow hijack
I used the trick of the HITCON 2016 challenge "house of orange". That is, we use the unsorted bin attack to attack the _IO_list_all variable in libc. Since the content of that _IO_list_all variable is not chunk-looked, we'll get an exception. When facing exception, libc will flush the IO, using the _IO_list_all it self! So, we change the _IO_list_all to somewhere in main_arena, since we can control some of the address (the bins address) partially, we can get this work by use a fake file struct. This is almost the same as that challenge. Search for some writeups, there are plenty of them, and I don't want to add one more.

# exp.py
final exploit is presented in the same directory. Note that this exploit not always work, you may need several times. That is because the house of orange trick depends on some condition in the IO fresh process. And since we cannot fully control that process, we can only hope that the condition can be passed. Fortunately, that condition is very likely to be passed, so this exploit works if you try several times.
