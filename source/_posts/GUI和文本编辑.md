---
title: GUI和文本编辑
tags:
  - Linux
category:
  - Linux
  - 基础学习
abbrlink: 4f7c637d
date: 2018-06-24 22:10:28
---

#### 1. 远程X的设置
X Window系统是一个网络化的视窗系统，它能 够在位映象的屏幕上显示窗口式的文本和图形。
X Window系统还可以叫做X11或者X
使用X 的两种启动方式：
1 先进入命令行界面，然后运行：startx 
2 开机自动进入图形界面：在/etc/inittab中配置运行 级别为5 

在X应用程序后面加上-display和显示的名字 
如：xeyes -display  192.168.0.3:0 
表示xeyes在192.168.0.3的显示0上显示

远程的X安全性
 基于主机的访问控制
 - xhost  +  允许任何人访问
 - xhost  -   限制访问 
- 在限制访问下为某个主机打开访问控制，使用 xhost +主机名（或IP）
- 去除某个主机的连接，使用 xhost  -主机名（或IP）s

#### 2.vi（教案第3章P21中红色标注的命令）
![image.png](https://upload-images.jianshu.io/upload_images/5443560-ad625889a788ed49.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

