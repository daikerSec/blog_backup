---
title: CTF中代码审计小trick(未完)
tags:
  - ctf
  - Web
  - 代码审计
category: [漏洞挖掘,代码审计,php]
abbrlink: '4249e474'
date: 2017-05-04 21:14:14
---
# 0x00 弱类型
强类的语言遇到函数引数类型和实际调用类型不匹配的情况经常会直接出错或者编译失败；而弱类型的语言常常会实行隐式转换，或者产生难以意料的结果
<!--more-->
也就是说，其实弱类型式其实式语言帮我们做了转换，好处是我们编程的时候可以省很多力，但是方便的同时也带来一些问题。注意的是，`python`并不是一门弱类型的语言。
1. string转int
`php`在将`string`转化成`int `的时候会把后面的字母舍掉。
比如 '132a'会被转化为123。又比如’aaa‘会被转化为为0。
受到影响的:`intval()`,`==`,`>`,'`<`等。看到具体的例子。
```php
is_numeric(@$a["str"])?die("eroor"):NULL;
    if(@$a["str"]){
       if ($a["str"]>2016){
       echo $flag;
    }
   }
```
这时只需要传入2017aaa就可以绕过
2. 进制转化
会自动转化进制，而且支持科学计数法
``php
 var_dump(0x10==16);
 var_dump(020==16);
 var_dump(2e1==20);
``
这些都是正确的，举个例子
```php
?php
$md51 = md5('QNKCDZO');
$a = @$_GET['a'];
$md52 = @md5($a);
if(isset($a)){
if ($a != 'QNKCDZO' && $md51 == $md52) {
    echo "nctf{*****************}";
} else {
    echo "false!!!";
}}
else{echo "please input a";}
?>
```
这时只要找出两个数的md5都是0e开头的就可以。
具体哪些，看这一篇[PHP处理0e开头md5哈希字符串缺陷/bug](http://www.cnblogs.com/Primzahl/p/6018158.html)
<!-- more -->
# 0x01 strcmp
strcmp(array,string)=null=0
具体例子
```php
<?php
$pass=@$_POST['pass'];
$pass1=***********;//被隐藏起来的密码
if(isset($pass))
{
    if(@!strcmp($pass,$pass1)){
    echo "flag:nctf{*}";
  }else{
  echo "the pass is wrong!";
}
}else{
  echo "please input pass!";
}
?>
```
传进一个数组就行
# 0x02 array_search()与in_array()
传进的string被转化为0的情况
```php
$array=array(13);
var_dump(strcmp($array,'abc')==true );
```
```
$array=array(0=>'a','b');
var_dump(array_search('b',$array) == false ); //false
var_dump(array_search('c',$array) == false ); //true
var_dump(array_search('a',$array) == false ); //true  特例，刚好找到是0 0==flase
```
# 0x03 md5
```php
$array=array(0=>'a','b');
$b=array(0);
var_dump(md5($array)===md5($b)); //true
```
两个数组的md5一样
# 0x04 eregi
可以被截断
```php
$c=@$_GET['cat'];
$d=@$_GET['dog'];
if(@$c[1]){
    if(!strcmp($c[1],$d) && $c[1]!==$d){
		
        eregi("3|1|c",$d.$c[0])?die("nope"):NULL;
        strpos(($c[0].$d), "isccctf2017")?$v3=1:NULL;
		
    }
```
构造截断就好
# 0x05 file_put_content和unlink
# 0x06 rand
# 0x07 end(array)和array[length(array)-1]
# 0x08 未初始化变量漏洞