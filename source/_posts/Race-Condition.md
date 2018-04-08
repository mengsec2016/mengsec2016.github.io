---
title: 条件竞争（Race Condition）
date: 2018-04-07 19:55:23
tags: 
	- 条件竞争
---

在0CTF2018中划了划水，学到了不少东西，赛后总结整理下"条件竞争"漏洞知识点。
<!-- more -->

## 1. 漏洞简介

条件竞争是指一个系统的运行结果依赖于不受控制的事件的先后顺序。当这些不受控制的事件并没有按照开发者想要的方式运行时，就可能会出现 bug。尤其在当前我们的系统中大量对资源进行共享，如果处理不当的话，就会产生条件竞争漏洞。

来举个例子:
```
#-*-coding:utf-8-*-
import threading
COUNT = 0

def Run(threads_name):
	global COUNT
	read_value = COUNT
	print "COUNT in Thread-%s is %d" % (str(threads_name), read_value)
	COUNT = read_value + 1

def main():
	threads = []
	for j in range(10):
		t = threading.Thread(target=Run,args=(j,))
		threads.append(t)
		t.start()
	for i in range(len(threads)):
		threads[i].join()
	print("Finally, The COUNT is %d" % (COUNT,))

if __name__ == '__main__':
	main()

```
这是一个很简单的多线程计数，按照程序的逻辑，到程序执行完毕，`COUNT`的值应该是10，但事实并不是这样，`COUNT`的值不但达不到10，而且每次执行的效果都不一样。

![](http://osn75zd5c.bkt.clouddn.com/Race%20Condition-1.png)

Why？

我们可以假设，当`COUNT`是3时，线程th1读取`COUNT`，然后读取到了3，然后CPU将控制权给了线程th2,线程th2同样对其进行读取，还是3，然后接下来th1和th2都将`COUNT`加到4，然而我们的预期是加到5。在这里，程序中多个线程之间就产生了资源竞争，这种情况发生了多次，于是最后的结果就和我们的预期不一样了。

## 2. Web中的条件竞争

由于网站的特殊性，Web服务器处理多用户的请求时，是并发进行的，因此，如果并发处理不当或者相关逻辑操作设计的不合理的时候，就会导致条件竞争漏洞。简单点说就是在你要做一件事情的时候用很快的速度插了个队并做了另外一件事。而这就导致了一些不好的事情。

在很多网站中都会包含上传文件或者从远端获取文件保存在服务器的功能，比如修改头像。来看一个简单的例子：

```
<?php
  if($_FILES["file"]["error"] > 0)){
    move_uploaded_file($_FILES["file"]["tmp_name"],"upload/" . $_FILES["file"]["name"]);
    //check file
    unlink("upload/"._FILES["file"]["name"]));
    //...
 }
?>
```
这段代码看似一切正常，先将上传的文件上传到Web目录，然后检查文件的安全性，如果发现文件不安全就马上通过`unlink()`将其删除。但是，当程序在服务端并发处理用户请求时问题就来了。如果在文件上传成功后但是在相关安全检查发现它是不安全文件删除它以前，这个文件就被执行了那么会怎样呢？

假设攻击者上传了一个用来生成恶意shell的文件，在上传完成和安全检查完成并删除它的间隙，攻击者通过不断地发起访问请求的方法访问了该文件，该文件就会被执行，并且在服务器上生成一个恶意shell。至此，该文件的任务就已全部完成，至于后面发现它是一个不安全的文件并把它删除的问题都已经不重要了，因为攻击者已经成功的入侵了服务器。

## 3. CTF实例

### 3.1 CUMT平台上的 上传三

[题目地址](http://202.119.201.199/challenge/web/uploadfile/)

使用burp抓包上传一个shell，先将文件名改成`233.jpg`

![](http://osn75zd5c.bkt.clouddn.com/Race%20Condition-2.png)

要求上传可执行文件，改成`233.php`

![](http://osn75zd5c.bkt.clouddn.com/Race%20Condition-3.png)

两个flag到手

然后告诉你这个文件扩展名在黑名单里，尝试`php4`,`php5`,`phtml`,发现`phtml`不在黑名单，但文件还是被删掉了。

![](http://osn75zd5c.bkt.clouddn.com/Race%20Condition-4.png)

文件还是在服务器中存在过的，这就存在了条件竞争漏洞，在文件被删除之前，我们可以访问它来执行命令。

先写个py脚本循环访问上传的文件，然后burp的Intruder模块多次上传文件，即可获得flag。

```
import requests
url = 'http://202.119.201.199/challenge/web/uploadfile/upload/233.phtml'
while True:
    r = requests.get(url)
    if 'flag' in  r.text:
        print r.text
```

![](http://osn75zd5c.bkt.clouddn.com/Race%20Condition-5.png)

### 3.2 0CTF2018-Easy User Manage System

题目中把IP当作手机，通过开放80端口的HTTP服务来接收注册账号时的验证码。
收到的验证码在HTTP的请求头里。
```
202.120.7.196 - - [03/Apr/2018 20:31:15] "HEAD /?037d95ce2da397602f4acc0b3227fcbc HTTP/1.1" 200 -
```

注册完账号后，发现提示
```
If you make your phone to be 8.8.8.8, I will give you a flag.
```
其中还给了一个页面用来修改IP地址。

![image](http://osn75zd5c.bkt.clouddn.com/20180CTF-Web-EUMS-1.png)


题目考察的是多个session进行条件竞争。

我们首先成功注册一个账号，并且通过IP验证，为了实现有多个session，分别在两个不同的浏览器上登陆。

![image](http://osn75zd5c.bkt.clouddn.com/20180CTF-Web-EUMS-2.png)

此时两个都在登录状态，然后都到修改IP的那个界面，其中一个提交自己VPS的IP，如果IP地址重复的话，可以通过IP的16进制来进行绕过，提交之后就会跳转，让你输入验证码，输入验证码后暂时不用提交，此时去另一个浏览器上页面填写IP地址为8.8.8.8。如图：

![image](http://osn75zd5c.bkt.clouddn.com/20180CTF-Web-EUMS-3.png)

然后直接使用burp进行抓包，先点击提交8.8.8.8IP的那个，然后再提交验证码，这两个包都会被burp拦截，然后直接点击Intercept off放行，即可获得flag。

![image](http://osn75zd5c.bkt.clouddn.com/20180CTF-Web-EUMS-4.png)

在该题目中，服务器通过session对请求顺序建立了锁，因此我们需要多个session，使用两个浏览器登录同一个账户即可。在将IP改为8.8.8.8时，有短时间的网络请求堵塞，我们在这个时间段，使用另一个session提交请求，即可通过验证，成功将IP改为8.8.8.8，然后获得flag。这个题目算是一个对数据库操作的条件竞争漏洞的典型例子。

## 4. 总结以及漏洞修复

条件竞争漏洞产生的很大一部分原因是程序不严谨，对于并发操作没有做好限制，毕竟开发者在进行代码开发的时候，常常倾向于代码会以线性的方式执行，而并行服务器会同时执行多个线程，这就会导致意想不到的结果。

条件竞争漏洞的修复主要看开发者，以上述的Web漏洞为例：
- 对于数据库的操作，比较正统的方法是设置锁
- 对于文件上传，“引狼入室”的方法不可取，最好在上传到目录之前就进行充分的检测，最好使用白名单。


## 5. 参考链接

- http://www.361way.com/python-thread/3425.html
- http://wiki.secbug.net/web_race-condtion.html
- https://blog.csdn.net/u011377996/article/details/79511160
- https://coxxs.me/676