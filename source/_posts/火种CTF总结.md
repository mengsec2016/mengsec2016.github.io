---
title: 火种CTF总结
date: 2017-09-10 16:19:51
tags:
	- CTF
---
## 0x01 Web
印象最深刻的就是最后一道Web题，这道题是校赛的一个sql注入题改的，遗憾的是，在大表哥的提示后，我也没能做出来。但是Get到了SQL注入的一个新姿势：
<!-- more -->
正常查询：

```
mysql> select * from test where id = 1;
+----+------+------+
| Id | QAQ  | QAQ1 |
+----+------+------+
|  1 | 123  | 233  |
+----+------+------+
1 row in set (0.00 sec)
```
错误查询：

```
mysql> select * from test where id = -1;
Empty set (0.00 sec)
```
非正常查询：

```
mysql> select * from test where id = -1=(0)=1;
+----+------+------+
| Id | QAQ  | QAQ1 |
+----+------+------+
|  1 | 123  | 233  |
+----+------+------+
1 row in set (0.00 sec)
```
这个语句很容易理解，首先是
```
select * from test where id = -1
```
这句话为假，即它的值为0，但是0 = 0，就成立了，成真，所以
```
select * from test where id = -1=(0)
```
的值为真，即为1，1=1成立，因此该句成立，从而返回查询结果。
与之类似

```
mysql> select * from test where id =-1=(1)=0;
+----+------+------+
| Id | QAQ  | QAQ1 |
+----+------+------+
|  1 | 123  | 233  |
+----+------+------+
1 row in set (0.00 sec)
```
甚至不等号"<>",都可以。
```
mysql> select * from test where id =-1<>(1)<>0;
+----+------+------+
| Id | QAQ  | QAQ1 |
+----+------+------+
|  1 | 123  | 233  |
+----+------+------+
1 row in set (0.00 sec)
```
中间的语句可以用来构造Bool条件。
SQL语句实在是太灵活了，感觉是，只有想不到，没有做不到。。
## 0x02 Misc
杂项不愧是杂项，每次做题总能遇到没见过的。
1. Thumbs.db文件
> Thumbs.db是一个用于Microsoft Windows XP或mac os x缓存Windows Explorer的缩略图的文件。

这个题目给了一堆关于海贼王的图片，里面还有一个Thumbs.db文件，百度下载thumbs_viewer，可以打开该文件，然后获得两个图片，其中一个图片的原图是有问题的，直接Notepad++打开搜索字符串，获得Flag.

2..ivs文件
这种文件可用来破解wifi密码。

这个题目给了一个www.ivs文件和一个带密码的压缩包，推测通过www.ivs文件获取压缩包密码，使用Aircrack-ng软件打开.ivs文件：

```
cygwin warning:
  MS-DOS style path detected: E:\CTF\\xE6\xAF\x94\xE8\xB5\x9B\\xE7\x81\xAB\xE7\xA7\x8DCTF\wifi\www.ivs
  Preferred POSIX equivalent is: /cygdrive/e/CTF/\xE6\xAF\x94\xE8\xB5\x9B/\xE7\x81\xAB\xE7\xA7\x8DCTF/wifi/www.ivs
  CYGWIN environment variable option "nodosfilewarning" turns off this warning.
  Consult the user's guide for more details about POSIX paths:
    http://cygwin.com/cygwin-ug-net/using.html#using-pathnames
Read 36977 packets.

   #  BSSID              ESSID                     Encryption

   1  78:EB:14:0D:2B:10  ceshi                     WEP (36960 IVs)
   2  1C:FA:68:D3:1B:2A  FMCN                      Unknown
   3  00:87:36:1F:CB:C3  360WiFi-CBC3              Unknown
   .......

Index number of target network ?
```
选择1并回车
然后提示

```
KEY FOUND! [ 31:32:33:34:35 ] (ASCII: 12345 )
```
因此压缩包密码是12345.
打开压缩包使用wireshark打开。导出其中的文件。
其中有个文件内容为

```
username=%E7%AD%94%E6%A1%88&password=key%7Bbalabala%7D&image.x=51&image.y=45
```
password即为flag。
## 0x03 Wireshark导出数据包内文件的方法

打开文件后，左上角文件-导出对象-HTTP
选择文件保存即可。