---
title: shell和shell编程
tags:
  - Linux
category: [Linux,基础学习]
abbrlink: fb0a66e4
date: 2018-06-24 22:10:56
---

#### 1. shell变量赋值
- 任何字符串都可以作为变量的值赋给某个变量； 
- 如果字符串中包含空格、tab或换行符时，应该用 引号（单、双都可以）括起来。
- 变量的值中包含多个连续的空格在输出显示时会当 作一个空格来处理

```
root@DESKTOP-4E87I7L:/tmp# a=5

```
#### 2. 变量引用
`$`+变量名
```
root@DESKTOP-4E87I7L:/tmp# echo $a
5
```
#### 3. 系统变量PATH、HOME、PWD、PS1、环境文件（profile和bashrc的差别）
- PATH 是操作系统用于查找来自命令行或终端窗口的必需可执行文件的系统变量。
比如执行`cat 1.txt`。这个cat 是在`/usr/bin/cat`这个路径，但是当前可以找到它，是因为`PATH`这个变量里面有`/usr/bin`这个
- HOME 家目录
正常的话,root用户的家目录在  `/root`,其他用户在`/home/用户名`

- PS1
提示符
如
```
root@DESKTOP-4E87I7L:/tmp# echo $PS1
\[\e]0;\u@\h: \w\a\]${debian_chroot:+($debian_chroot)}\u@\h:\w\$
```
其中一些特殊字符的代码
\\$ 显示$符作为提示符，如果用户是root的话，则 显示#号。 
\\\ 显示反斜杠。 
\d 显示当前日期。 
\h 显示主机名。  
\t 显示当前时间。  
\w 显示当前工作目录的路径。 
- PS2
PS2 变量展开的方式与 PS1 相同，其展开值用作次提示符字符串。用于提示接续你尚未完成输入的命令。默认为`>`
比如
![](https://upload-images.jianshu.io/upload_images/5443560-e4162d4da46ba5f5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
稍作修改。
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-9f5890c8316b646a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
- PWD
当前路径,作用跟`pwd`一样
- 环境文件（profile和bashrc的差别）
profile:每个用户都可使用该文件输入专用于自己使用的shell信息,当`用户登录`时,该文件仅仅执行一次!
bashrc:该文件包含专用于你的bash shell的bash信息,当`登录时`以及 `每次打开新的shell`时,该文件被读取.


#### 4. shell通配符

用来匹配多个文件名或目录名的特殊字符叫通配 符。 
\*   匹配任意个（含0个）字符 
?   匹配任意一个字符 
[list] 匹配其中之一的字符 
[!list]   匹配不在其中的字符

如`1*3.txt`匹配1223.txt
如`1?3.txt`匹配123.txt
如`[abcd]1.txt`匹配a1.txt
如`[a-d]1.txt`匹配a1.txt
如`[!abc]1.txt`匹配d1.txt

#### 5. 引号
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-0b00669a4de56c6f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
双引号会解析

#### 6. 正则表达式
跟通配符的区别
正则表达式和shell的特殊字符异同点
正则表达用点匹配任意一个字符，相当于shell的问号。 
.\*匹配零或多个字符，相当于shell的\*
 []用法和shell一样，只是用^代替了!表示不匹配
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-fe35539e4f2f2d49.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-c6e0242eceb1752d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-9d54af6b41fa6656.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)





#### 7. 输入输出命令
标准输入输出 
每一个Linux命令都有３个与之相关的输入输出流： 
- stdin     标准输入，命令默认的输入位置 
- stdout   标准输出，命令默认的输出位置 
- stderr    标准错误输出，也是命令的输出位置，用于输出错误及诊断信息。
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-5ea97dc03087fe69.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
`重定向`
比如把应该输出到屏幕的输出到文件
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-8187538ecfb73c0e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

`2>&1`解释
2 是标准错误，1是标准输出，就是把标准错误发送到标准输出。注意1要加个`&`，不然就会重定向到文件1

`cat 1.txt >/dev/null`解析
这里的`/dev/null`是黑洞。把输出的重定向到黑洞。等同于不输出


#### 8. 管道
命令A | 命令B
这个就是管道，把命令A 的内容的标准输出流当成命令B的标准输入流，![图片.png](https://upload-images.jianshu.io/upload_images/5443560-29846072489f7b92.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

举个例子
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-1024f4680905f91b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
cat 1的结果`123`传递给`grep 2`


#### 9. shell脚本
变量读取
判断
循环
$# 参数个数
$0 文件名
$1 第一个参数


```
#! /bin/sh
read -p "please input yes or not: " yn
echo $yn
if [ "${yn}"=="Y" -o "${yn}"=="y" ]; then
	echo "OK, continue"
	exit 0
elif [ "${yn}"=="Y" -o  "${yn}"=="y" ]; then
	echo "oh,NO"
	exit 0
else
	echo "please input yes or not"
fi
if [ $# == 1 ]:
	echo "请添加参数"
	exit 0
fi
echo "Filename: "$0
i=0
while [ "${i}" != $1 ]
do
	i=$(($i+1))
	echo $i
done
```