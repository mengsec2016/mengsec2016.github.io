---
title: 使用Volatility解决CTF取证类题目
date: 2018-10-20 13:07:53
tags:
	- CTF
	- Fornesics
	- Volatility
---

这段时间做CTF遇到了个内存取证的题目，由于工具用的不熟练，最后没及时做出来，赛后整理整理Volatility的常用命令。

<!-- more -->

## 1. Volatility 常用命令

### 1.1 imageinfo

通过这个命令来获取内存镜像的摘要信息，比如OS，Service Pack和硬件架构等，个人认为这个命令最主要的作用是给进一步分析指明`profile`，也就是使用其他插件时加载的配置文件。

```
volatility -f easy_dump.img imageinfo
```

![1](https://image.mengsec.com/CTF-Volatility/1.png)

可以使用`--info`参数来查看Volatiliity已经添加的profile和插件等信息。

![2](https://image.mengsec.com/CTF-Volatility/2.png)

### 1.2 kdbgscan

`kdbgscan`这个插件可以扫描文件的profile的值，通常扫描结果有多个，只有一个结果完全正确。kdbgscan和`imageinfo`仅适用于Windows内存镜像。

```
volatility -f easy_dump.img kdbgscan
```

![3](https://image.mengsec.com/CTF-Volatility/3.png)

### 1.3 pslist

 `pslist`可以用来列出运行的进程。如果Exit所在的一列显示了日期时间，则表明该进程已经结束了。

```
volatility -f easy_dump.img --profile=Win7SP1x64 pslist
```

![4](https://image.mengsec.com/CTF-Volatility/4.png)

### 1.4 hivelist

`hivelist`可以用来列举缓存在内存中的注册表。

```
volatility -f easy_dump.img --profile=Win7SP1x64 hivelist
```



![5](https://image.mengsec.com/CTF-Volatility/5.png)



### 1.5 filescan

`filescan`可以扫描内存中的文件

```
volatility -f easy_dump.img --profile=Win7SP1x64 filescan
```

![6](https://image.mengsec.com/CTF-Volatility/6.png)

### 1.6 dumpfiles

 `dumpfiles`可以将内存中的缓存文件导出

```
volatility -f easy_dump.img --profile=Win7SP1x64 dumpfiles -Q 0x00000000236eb5e0 -D ./ -u
```



![7](https://image.mengsec.com/CTF-Volatility/7.png)



以上只是一些基本操作，具体可以查阅官方手册

> https://github.com/volatilityfoundation/volatility/wiki/Command-Reference

## 2. CTF案例

### 2.1 JarvisOJ 取证题

题目下载地址

```
链接: https://pan.baidu.com/s/1hvAhL78aDS4IDxatF3uH0A 提取码: 943u
```

解压之后得到两个文件，其中一个是vmem文件，使用volatility进行分析。

![8](https://image.mengsec.com/CTF-Volatility/8.png)

使用pslist列举运行中的进程，发现有TrueCrypt.exe,而且没有退出。

![9](https://image.mengsec.com/CTF-Volatility/9.png)

推测题目所给的另一个文件是使用TrueCrypt进行加密了的。进程没有退出，那么加密的密钥有可能就在进程中，将该进程作为文件导出。

![10](https://image.mengsec.com/CTF-Volatility/10.png)

然后使用Elcomsoft Forensic Disk Decryptor进行解密，首先在导出的内存镜像中搜索key.

![11](https://image.mengsec.com/CTF-Volatility/11.png)

因为是文件，选择TrueCrypt(container)。

![12](https://image.mengsec.com/CTF-Volatility/12.png)

![13](https://image.mengsec.com/CTF-Volatility/13.png)

选中待解密文件和dmp镜像，软件会自动寻找key,然后将key保存。

![14](https://image.mengsec.com/CTF-Volatility/14.png)

![15](https://image.mengsec.com/CTF-Volatility/15.png)

使用保存的key对文件进行解密，然后挂载即可获得flag。

![16](https://image.mengsec.com/CTF-Volatility/16.png)

![17](https://image.mengsec.com/CTF-Volatility/17.png)



### 2.2 护网杯2018-Misc-Easy_dump

题目下载地址

```
链接：https://pan.baidu.com/s/1Vwp7MeM-7hkTMGeRu_aKTg 提取码：vw1r
```

是一个img文件，使用volatilty进行分析。

```
volatility -f easy_dump.img imageinfo
```

![18](https://image.mengsec.com/CTF-Volatility/18.png)

使用pslist查看进程。

```
volatility -f easy_dump.img --profile=Win7SP1x64 pslist
```

![19](https://image.mengsec.com/CTF-Volatility/19.png)

有一个DumpIt.exe，使用memdump命令将其dump出来。

```
volatility -f easy_dump.img --profile=Win7SP1x64 memdump -p 2888 -D ./
```

![20](https://image.mengsec.com/CTF-Volatility/20.png)

使用foremost进行分析，发现有个压缩包，解压后获得一个message.img

![21](https://image.mengsec.com/CTF-Volatility/21.png)

file命令检测一下，发现是ext2文件系统数据。

![22](https://image.mengsec.com/CTF-Volatility/22.png)

使用DiskGenius打开message.img。找到一个vim的swp文件，

![23](https://image.mengsec.com/CTF-Volatility/23.png)

使用`vim -r`命令恢复，得到一段字符串

```
yispyweise!dmsx_tthv_arr_didvi
```

在磁盘目录中找到一个hint.txt。

![24](https://image.mengsec.com/CTF-Volatility/24.png)

看起来很像坐标点，使用python的PIL库画出来。

```
from PIL import Image

file = open('hint.txt','r')
data = file.read()
pic = Image.new('RGB',(300,300))
data = data.split('\n')
for i in data:
	a = i.split(' ')
	x = int(a[0])
	y = int(a[1])
	pic.putpixel([x,y],(255, 255, 255))
pic.show()
pic.save('result.png')
```

![25](https://image.mengsec.com/CTF-Volatility/25.png)

扫描一下，

```
Here is the vigenere key: aeolus, but i deleted the encrypted message。
```

维吉尼亚密码，在线解码即可

![26](https://image.mengsec.com/CTF-Volatility/26.png)