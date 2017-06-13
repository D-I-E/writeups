# Writeup

1. 用dis和uncompile2查看pyc，得到完整的str串。

2. 观察得到flag3函数的逻辑，将给出字符串逆过来解base64再逆过来并且每个字符减一即可。

# Exp

```python
a = '=cWbihGfyMzNllzZ0cjZzMWN5cTM4YjYygTOycmNycWNyYmM1Ujf'

import base64

print ''.join(map(lambda x: chr(ord(x)-1), base64.b64decode(a[::-1])))[::-1]
```

# Other writeups and resources

(NONE)
