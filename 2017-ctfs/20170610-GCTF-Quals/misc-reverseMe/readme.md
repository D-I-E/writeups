# Writeup

1. 观察到头尾发现反序jpg的magic number（FF D8和FF D9），用python将字节逆过来即可看到flag图片。

# Exp

```python
f=open('flag.jpg','wb')
f.write(open('reverseMe','rb').read()[::-1])
```

# Other writeups and resources

(NONE)
