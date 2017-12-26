---
title: SSH正向代理与反向代理
date: 2017-12-26 21:26:32
tags:
	- 内网穿透
---
在X-NUCA 2017决赛中用到了些内网穿透的知识，但是我只会用reGeorg+Proxychains来进行内网穿透，效果很不理想，赛后研究下用SSH来内网穿透。
<!-- more -->
## 1. 知识点

### 1.1 准备工作

开启SSH的转发功能:在`/etc/ssh/sshd_config`中末尾加入

	GatewayPorts yes

然后重启SSH

	service ssh restart

### 1.2 正向代理

正向代理的典型例子是主机(A)通过一台可以访问的主机(B)访问主机(C)提供的服务。 主机A不能直接访问主机C提供的服务，但是主机A可以访问主机B，主机B可以访问到主机C的服务，那我们可以在主机A上使用以下命令

	ssh -CNfL a_port:c_ip:c_port b_user@b_ip

### 1.3 反向代理

反向代理的作用可以认为是把内网中的主机(A)暴露出来，以便于所有的主机都可以访问到主机A的服务。假定我们使用一台公网可以访问的主机(B)来给主机A做反向代理，那么命令如下

	ssh -CNfR b_port:127.0.0.1:a_port b_user@b_ip

### 1.4 SSH参数介绍

- -N 告诉 SSH 客户端，这个连接不需要执行任何命令，也就是说不需要打开远程 shell，仅仅做端口转发；
- -T 不为这个连接分配 TTY。其中 -N,-T 两个参数可以放在一起用，代表这个 SSH 连接只用来传数据，不执行远程操作；
- -f 告诉SSH客户端在后台运行，要关闭这个后台连接，就只有用 kill 命令去杀掉进程；
- -L 做本地映射端口，需要注意被冒号分割的三个部分含义，下面做详细介绍；
- -C 压缩数据传输；
- -g (GatewayPorts) 默认只转发本地发送的数据，如果要转发其它服务器的客户端请求，则需要添加该参数。

## 2. 拓扑

![](http://osn75zd5c.bkt.clouddn.com/Blog_SSH%E6%AD%A3%E5%90%91%E4%BB%A3%E7%90%86%E4%B8%8E%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86_tuopu.png)

## 3. 测试
从上面的拓扑图中，hacker是不能直接访问处于内网中的Web服务器的Web服务。我们可以通过中间的代理服务器来建立一条SSH隧道来达成这一目的。

第一步，将内网的Web服务器反向连接到中间的代理服务器中。

执行命令

	ssh -p 22 -qngfNTR 6666:localhost:22 root@172.19.0.2

![](http://osn75zd5c.bkt.clouddn.com/Blog_SSH%E6%AD%A3%E5%90%91%E4%BB%A3%E7%90%86%E4%B8%8E%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86_1.png)

然后查看Web服务器中的进程

![](http://osn75zd5c.bkt.clouddn.com/Blog_SSH%E6%AD%A3%E5%90%91%E4%BB%A3%E7%90%86%E4%B8%8E%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86_2.png)

此时在代理服务器上，已经开始在6666端口开始监听了。

![](http://osn75zd5c.bkt.clouddn.com/Blog_SSH%E6%AD%A3%E5%90%91%E4%BB%A3%E7%90%86%E4%B8%8E%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86_3.png)

第二步，hacker在自己机器上执行命令

	ssh -p 6666 -qngfNTD 6767 root@172.17.0.3

执行之后就可以直接穿透网络，进入到内网，本地使用代理127.0.0.1：6767就能访问到内网中。

我们直接在Web服务器上用python开启一个HTTP服务

![](http://osn75zd5c.bkt.clouddn.com/Blog_SSH%E6%AD%A3%E5%90%91%E4%BB%A3%E7%90%86%E4%B8%8E%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86_4.png)

然后在hacker中使用proxychains进行代理访问127.0.0.1的8080端口，即可成功的访问到刚刚用python开启的Web服务

![](http://osn75zd5c.bkt.clouddn.com/Blog_SSH%E6%AD%A3%E5%90%91%E4%BB%A3%E7%90%86%E4%B8%8E%E5%8F%8D%E5%90%91%E4%BB%A3%E7%90%86_5.png)


于此，我们成功的在hacker与内网之间建立了一条SSH隧道。




## 参考链接

[SSH如何反向代理稳定穿透内网](https://www.anquanke.com/post/id/86596 "SSH如何反向代理稳定穿透内网")

[SSH正向与反向代理](http://blog.csdn.net/dliyuedong/article/details/49804825 "SSH正向与反向代理")