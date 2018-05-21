---
title: PWN环境搭建
tags:
  - pwn
category: [漏洞挖掘,二进制漏洞]
abbrlink: 11af4bf6
date: 2018-03-18 15:02:16
---
## 0x00 关闭安全机制
1.关掉DEP/NX（堆栈不可执行）
```sh
gcc  -z execstack -o pwnme pwnme.c
```
2.关掉Stack Protector/Canary（栈保护）
```sh
gcc -fno-stack-protector -o pwnme pwnme.c
```

<!--more-->
3.关掉程序ASLR/PIE（程序随机化保护）
```sh
gcc -no-pie -o pwnme pwnme.c
```
4.关闭整个linux系统的ASLR保护
```sh
su - 
echo 0 > /proc/sys/kernel/randomize_va_space
exit
```
5.打开整个linux系统的ASLR保护
```sh
su -
echo 2 > /proc/sys/kernel/randomize_va_space
exit
```
6. 64位linux下面的GCC编译出一个32位可执行程序 加参数`- m32`
```sh
gcc -m32 -z execstack -fno-stack-protector -o pwnme pwnme.c
```
另外说明下在ubuntu上如果要用 -m32 参数就要安装如下的库：
```sh
$ sudo apt-get install build-essential module-assistant  
$ sudo apt-get install gcc-multilib g++-multilib 
```
## 0x01 安装pwntools
```sh
pip install pwntools
```
## 0x02 安装peda
```sh
git clone https://github.com/longld/peda.git ~/peda
echo "source ~/peda/peda.py" >> ~/.gdbinit
```
## 0x03 绑定端口
```sh
socat tcp-l:端口号，reuseaddr，fork exec:程序位置
```