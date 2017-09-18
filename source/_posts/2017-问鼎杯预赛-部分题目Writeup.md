---
title: 2017-问鼎杯预赛-部分题目Writeup
date: 2017-09-18 18:08:02
tags:
	- CTF
	- Writeup
	- 问鼎杯
---

在火车上比的，就做了一部分题目，由于没有足够的时间做题，也没能进决赛/(ㄒoㄒ)/~~
<!-- more -->
## Web
### 0x01 老眼昏花
	
直接点击链接进入，提示

	Can you tell me what year is this? 
	Year is not true.

尝试使用get传一个year的参数

	http://sec2.hdu.edu.cn/84cdc76cabf41bd7c961f6ab12f117d8/?year=2017
又提示

	Can you tell me what year is this? 
	Yes this year is 2017, but you can't input 7 in fact.
要求输入的不能有7，尝试一下浮点数

	http://sec2.hdu.edu.cn/84cdc76cabf41bd7c961f6ab12f117d8/?year=2016.999999999999999999999999999999999999999999999999999999999999999

直接访问即可获得flag

### 0x02 轻而易举

这个题是个社工题，一开始没人做出来，直到主办方给了提示

根据文章下面的作者找到后台地址
/fuckme/index.php
直接根据文章中提供的信息，可以暴力破解出：

	后台账号名为翟欣欣的qq邮箱
	847085251@qq.com
	密码为车牌号
	NB51A5
	
直接登录，在其中文章中有两篇待审核，其中一篇的下面有一个

	From [/b7010bcfcdb62922d4e4a5ec8d79fb33.php](/b7010bcfcdb62922d4e4a5ec8d79fb33.php)
直接将其加载网址后面访问即可获得flag

## Misc
### 0x01 画风不一样的喵
下载下来是一张图片，修改扩展名，得到一个压缩包，解压出来得到两张看起来相同的图片还有一个tips.txt，

	Although two days doing the same things, but day2 has a secret than day1
	-。-
这种两张图片的题上一次在某竞赛中出现过，当时不了解盲水印攻击没做出来，这次有了经验，直接上脚本，配合命令：

	python bwm.py decode day1.png day2.png test1.png

得到一张flag
![](http://ou0111n4v.bkt.clouddn.com/test1.png)

### 0x02 古典密码
这个题主要考察字频统计攻击，上“[求pa](https://quipqiup.com/)”网站在线解密

![](http://ou0111n4v.bkt.clouddn.com/QQ%E6%88%AA%E5%9B%BE20170916201404.png)

提交getflag
### 0x03 瞒天过海
只有一个名为++__++的文件，用winhex分析了一下发现是个数据包，导出了一个flag.rar的压缩包，里面有个flag.txt，但是加密了。
![](http://ou0111n4v.bkt.clouddn.com/QQ%E6%88%AA%E5%9B%BE20170916174625.png)
没办法只能继续找线索。在导出http数据流的时候发现了个py脚本，拖出来跑一下得到`passwd={No_One_Can_Decrypt_Me}`，输入密码解出flag.txt ： `WDCTF{Seclab_CTF_2017}`

### 0x04 小菜一碟
给了一张二维码gif，分离出四张图片，拼接一下得到一张二维码，扫码得到一堆十六进制，放入winhex保存为.pyc文件，pyc反编译py得到一个py脚本：

	#!/usr/bin/env python
	# encoding: utf-8
	# 访问 http://tool.lu/pyc/ 查看更多信息
	import random
	key = 'ctf'
	strr = '186,98,180,154,139,192,114,14,102,168,43,136,52,218,85,100,43'
	
	def func1(str1, key):
	    random.seed(key)
	    str2 = ''
	    for c in str1:
	        str2 += str(ord(c) ^ random.randint(0, 255)) + ','
	    
	    str2 = str2.strip(',')
	    return str2
	
	
	def func2(str2, key):
	    random.seed(key)
	    str1 = ''
	    for i in str2.split(','):
	        i = int(i)
	        str1 += chr(i ^ random.randint(0, 255))
	    
	    return str1
	
	print "func1:"+func1(strr, key)+"\n"
	print "func2:"+func2(strr, key)+"\n"
	print "func1(func2):"+func2(func1(strr, key), key)

其中func1()是加密函数，func2()是解密函数，strr中的内容是经过第一个函数加密后的字符串，所以我们只需要加上一句`print func2(strr, key)`

运行一下就可以得到`flag{U_r_Greatt!}

PS：Windows和Linux中python生成随机数机制有问题，这个代码只有在Linux下运行才可以获得flag