---
title: 解决msf内存不足不能启动的问题
tags:
  - Kali
  - Linux
  - tools
category: [渗透测试,工具使用]
abbrlink: 376537a6
date: 2018-03-15 14:50:54
---

## 0x00 问题
在vps里面跑msf，经常遇到内存不足，提示如下
<!--more-->
```
/opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/activesupport-4.2.10/lib/active_support/core_ext/kernel/agnostics.rb:7:in ``': Cannot allocate memory - infocmp (Errno::ENOMEM)
	from /opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/activesupport-4.2.10/lib/active_support/core_ext/kernel/agnostics.rb:7:in ``'
	from /opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/rb-readline-0.5.5/lib/rbreadline.rb:1815:in `get_term_capabilities'
	from /opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/rb-readline-0.5.5/lib/rbreadline.rb:2027:in `_rl_init_terminal_io'
	from /opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/rb-readline-0.5.5/lib/rbreadline.rb:2564:in `readline_initialize_everything'
	from /opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/rb-readline-0.5.5/lib/rbreadline.rb:3849:in `rl_initialize'
	from /opt/metasploit-framework/embedded/lib/ruby/gems/2.4.0/gems/rb-readline-0.5.5/lib/rbreadline.rb:4868:in `readline'
	from /opt/metasploit-framework/embedded/framework/lib/rex/ui/text/input/readline.rb:162:in `readline_with_output'
	from /opt/metasploit-framework/embedded/framework/lib/rex/ui/text/input/readline.rb:100:in `pgets'
	from /opt/metasploit-framework/embedded/framework/lib/rex/ui/text/shell.rb:375:in `get_input_line'
	from /opt/metasploit-framework/embedded/framework/lib/rex/ui/text/shell.rb:191:in `run'
	from /opt/metasploit-framework/embedded/framework/lib/metasploit/framework/command/console.rb:48:in `start'
	from /opt/metasploit-framework/embedded/framework/lib/metasploit/framework/command/base.rb:82:in `start'
```
内存不足，一直没有好的解决方案。最近看Linux的时候，看到Swap分区，想到一个解决方案
## 0x01 解决方案
vps默认安装的时候是没有安装swap分区的
```
[root@daiker ~]# top
top - 06:35:36 up 14:57,  2 users,  load average: 0.21, 0.09, 0.07
Tasks:  86 total,   1 running,  85 sleeping,   0 stopped,   0 zombie
%Cpu(s):  0.5 us,  0.0 sy,  0.0 ni, 99.5 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st
KiB Mem :  1016108 total,   240924 free,   518952 used,   256232 buff/cache
KiB Swap:        0 total,        0 free,        0 used.   247996 avail Mem 

```
我们可以给分配一个swap分区,命令如下

```sh
dd if=/dev/zero of=/home/swap bs=1024 count=512000
/sbin/mkswap /home/swap
/sbin/swapon /home/swap
```
然后查看swap分区
```
[root@daiker ~]# free -h
              total        used        free      shared  buff/cache   available
Mem:           992M        506M         74M         92M        411M        242M
Swap:          499M          0B        499M

```

msf成功开启