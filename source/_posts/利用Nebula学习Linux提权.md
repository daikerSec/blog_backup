---
title: 利用Nebula学习Linux提权
tags:
  - Linux
  - 提权
  - 渗透测试
category:
  - 渗透测试
  - 提权
  - Linux
abbrlink: 5c949747
date: 2018-06-04 17:00:24
---

## 0x00 Nebula介绍和玩法
Nebula 是# [Exploit Exercises ](https://exploit-exercises.com/)上的基础关
他涉及了基本的`源码级漏洞分析`、`提权`。可以通过官网下载镜像进行安装。
每一关都对应系统中以level开头的账号，密码与账号名相同（比如`Level01`,对应的系统帐号是`level0`1），每玩一关，都需要用对应的账号登录系统，然后进入到`/home/flag×`目录中，与该level相关的代码、数据等都放在于此。之后通过运行getflag 来验证是否提权成功

## 0x01 level00
>This level requires you to find a Set User ID program that will run as the “flag00” account. You could also find this by carefully looking in top level directories in / for suspicious looking directories.

查找suid的程序，直接通过find查找
<!--more-->

```sh
find / -perm -u=s -type f 2>/dev/null
```
看到比较奇怪的一个文件`/bin/.../flag00`
![image.png](https://upload-images.jianshu.io/upload_images/5443560-968153e5e4a3fb30.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
提权成功
![image.png](https://upload-images.jianshu.io/upload_images/5443560-38e7dea4087e2f0c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
是flag00不是level00了。
这里利用的是suid 提权。研究下原理
先看flag00的权限
![](https://upload-images.jianshu.io/upload_images/5443560-ddf0bd66d9fab286.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
有setUid
setUid的功能是
```
1、SUID权限仅对二进制程序有效。
2、执行者对于该程序需要具有x的可执行权限。
3、本权限仅在执行该程序的过程中有效。
4、执行者将具有该程序拥有者的权限。
```
再用IDA查看下flag00
```C

int __cdecl main(int argc, const char **argv, const char **envp)
{
  __gid_t v3; // ST18_4
  __uid_t v4; // ST1C_4

  v3 = getegid();
  v4 = geteuid();
  setresgid(v3, v3, v3);
  setresuid(v4, v4, v4);
  puts("Congrats, now run getflag to get your flag!");
  return execve("/bin/sh", (char *const *)argv, (char *const *)envp);
}
```
所以大体的原理就是`flag00 `属于`flag00`这个用户,在`level00`这个组。
在`level00`这个用户也在`level00`这个组里面，这里拥有执行权限,而程序又有`suid`，因此`level00`在运行这个程序的时候暂时性拥有这个`flag00`的权限，接下来执行一个`shell`，并且这个`shell`传进的环境继承刚刚的环境,因此`shell`运行的时候的权限还是属于`flag00`的

## 0x02 level01
>There is a vulnerability in the below program that allows arbitrary programs to be executed, can you find it?
To do this level, log in as the level01 account with the password level01. Files for this level can be found in /home/flag01.

```C
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  gid_t gid;
  uid_t uid;
  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  system("/usr/bin/env echo and now what?");
}
```
这个文件也有suid,关键在最后一句，我们能不能让最后一句执行shell。
这里面`/usr/bin/env `后面跟着的是环境变量中的可执行程序，正常这一句，应该要在环境变量中寻找echo 这个可执行程序
![image.png](https://upload-images.jianshu.io/upload_images/5443560-51d87655eb032c8c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/5443560-bb403037400503a2.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
这个时候就会执行正常的echo。那我们的思路是


>在/usr/bin这个环境变量之前添加个环境变量`/home/level01`，在'level01'里面有个我们自定义的echo.

这样不就执行我们自己的程序了
![image.png](https://upload-images.jianshu.io/upload_images/5443560-75e27c0b066bfa50.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x03 level02

>There is a vulnerability in the below program that allows arbitrary programs to be executed, can you find it?
To do this level, log in as the level02 account with the password level02. Files for this level can be found in /home/flag02.


```C
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>

int main(int argc, char **argv, char **envp)
{
  char *buffer;

  gid_t gid;
  uid_t uid;

  gid = getegid();
  uid = geteuid();

  setresgid(gid, gid, gid);
  setresuid(uid, uid, uid);

  buffer = NULL;

  asprintf(&buffer, "/bin/echo %s is cool", getenv("USER"));
  printf("about to call system(\"%s\")\n", buffer);
  
  system(buffer);
}
```
跟上面类似，就要构造USER的值来填补，就可以进一步调用`/bin/sh`
![image.png](https://upload-images.jianshu.io/upload_images/5443560-8ce2a50e7a50a783.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x04 level03

>Check the home directory of flag03 and take note of the files there.
There is a crontab that is called every couple of minutes.
To do this level, log in as the level03 account with the password level03. Files for this level can be found in /home/flag03.

在`/home/flag03`里面发现有一个文件`writable.sh`和`writable.d`
查看`writeable.sh`的内容
![image.png](https://upload-images.jianshu.io/upload_images/5443560-a88076a133a16e24.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
大意就是循环执行一遍writable.d文件夹底下的文件。然后删除。这个时候看题目，`There is a crontab that is called every couple of minutes.`几分钟会被调用一次。我们猜测可能是执行`writable.sh`
把我们要执行的东西写到 `writable.d`里面去
![image.png](https://upload-images.jianshu.io/upload_images/5443560-09048910817293bc.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
然后等个几分钟
![image.png](https://upload-images.jianshu.io/upload_images/5443560-326b1e34111dcb4e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

接下来我们用root身份来看下corntab.
![image.png](https://upload-images.jianshu.io/upload_images/5443560-74c7cc753e68f46b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/5443560-382ad96faf251a97.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)


每三分钟执行一次`writable.sh`
 ## 0x05 level04

>This level requires you to read the token file, but the code restricts the files that can be read. Find a way to bypass it :)
To do this level, log in as the level04 account with the password level04. Files for this level can be found in /home/flag04.

```C
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>

int main(int argc, char **argv, char **envp)
{
  char buf[1024];
  int fd, rc;

  if(argc == 1) {
      printf("%s [file to read]\n", argv[0]);
      exit(EXIT_FAILURE);
  }

  if(strstr(argv[1], "token") != NULL) {
      printf("You may not access '%s'\n", argv[1]);
      exit(EXIT_FAILURE);
  }

  fd = open(argv[1], O_RDONLY);
  if(fd == -1) {
      err(EXIT_FAILURE, "Unable to open %s", argv[1]);
  }

  rc = read(fd, buf, sizeof(buf));
  
  if(rc == -1) {
      err(EXIT_FAILURE, "Unable to read fd %d", fd);
  }

  write(1, buf, rc);
}
```
分析:查看文件
![image.png](https://upload-images.jianshu.io/upload_images/5443560-7ee53af01e3ece0d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
`token`这个文件的权限是`0600`，只允许flag04用户读取,没有读取权限。
但是flag04这个文件我们有执行权限，隶属于flag04用户，并且有suid。
简单分析源码，这个程序的主要功能就是读取文件输出。所以只要我们利用这个文件来读物token 就行，但是有个限制，就是读取的文件名不能叫做`token`。所以只需要利用软连接，建立一个名字中不含有`token`的文件，软链接到token 。

![image.png](https://upload-images.jianshu.io/upload_images/5443560-d30318a0f9bd3f7b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/5443560-356a30698bc1a87e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x06 level05
>Check the flag05 home directory. You are looking for weak directory permissions
To do this level, log in as the level05 account with the password level05. Files for this level can be found in /home/flag05.

![image.png](https://upload-images.jianshu.io/upload_images/5443560-8fec3b78daf9ddca.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
看到`.ssh`文件夹，推测可能是想通过ssh 登陆进来，但是`.ssh`文件夹的权限`700`。我们没有查看权限。这时候看到backup文件夹
![image.png](https://upload-images.jianshu.io/upload_images/5443560-a53be6bb86afe6bd.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
看到一个备份文件夹。
![image.png](https://upload-images.jianshu.io/upload_images/5443560-17ad621643eb194c.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
解压下，果然是`.ssh`的压缩，就可以利用私钥登陆
![image.png](https://upload-images.jianshu.io/upload_images/5443560-4c5f2065afbccb0f.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/5443560-801ef1892f28383a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
登陆成功

## 0x07 level06
>The flag06 account credentials came from a legacy unix system.
To do this level, log in as the level06 account with the password level06. Files for this level can be found in /home/flag06.

通过这句话`The flag06 account credentials came from a legacy unix system.`，比较旧版本的Unix的密码是放在`/etc/passwd`
![image.png](https://upload-images.jianshu.io/upload_images/5443560-a1d5b80a3510410a.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
这个时候我们就可以用`john`爆破，这里用的是`kali`上自带的
![image.png](https://upload-images.jianshu.io/upload_images/5443560-484f9d9e3d8606ad.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
然后登陆

## 0x08 level07
>The flag07 user was writing their very first perl program that allowed them to ping hosts to see if they were reachable from the web server.
To do this level, log in as the level07 account with the password level07. Files for this level can be found in /home/flag07.
源码
```perl
use CGI qw{param};

print "Content-type: text/html\n\n";

sub ping {
  $host = $_[0];

  print("<html><head><title>Ping results</title></head><body><pre>");

  @output = `ping -c 3 $host 2>&1`;
  foreach $line (@output) { print "$line"; }

  print("</pre></body></html>");
  
}

# check if Host set. if not, display normal page, etc

ping(param("Host"));

```

看这行代码`ping -c 3 $host 2>&1`,典型的命令注入，构造`host=127.0.01;whoami`就可以执行whoami

## 0x09 level08
>World readable files strike again. Check what that user was up to, and use it to log into flag08 account.
To do this level, log in as the level08 account with the password level08. Files for this level can be found in /home/flag08.

看到一个流量包
![image.png](https://upload-images.jianshu.io/upload_images/5443560-b2096557d4e9ec72.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
wireshark 追踪流，以16进制形式展开
![image.png](https://upload-images.jianshu.io/upload_images/5443560-fd871199d9ea41db.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
其中`7f`是删除键,所以密码为`backd00Rmate`

![image.png](https://upload-images.jianshu.io/upload_images/5443560-7aedc30548473071.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x0A level09
>There’s a C setuid wrapper for some vulnerable PHP code…
To do this level, log in as the level09 account with the password level09. Files for this level can be found in /home/flag09.

源码
```php
<?php

function spam($email)
{
  $email = preg_replace("/\./", " dot ", $email);
  $email = preg_replace("/@/", " AT ", $email);
  
  return $email;
}

function markup($filename, $use_me)
{
  $contents = file_get_contents($filename);

  $contents = preg_replace("/(\[email (.*)\])/e", "spam(\"\\2\")", $contents);
  $contents = preg_replace("/\[/", "<", $contents);
  $contents = preg_replace("/\]/", ">", $contents);

  return $contents;
}

$output = markup($argv[1], $argv[2]);

print $output;

?>
```
## 0x0B level10
>The setuid binary at **/home/flag10/flag10** binary will upload any file given, as long as it meets the requirements of the [access()](http://linux.die.net/man/2/access) system call.

源码

```C
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>

int main(int argc, char **argv)
{
  char *file;
  char *host;

  if(argc < 3) {
      printf("%s file host\n\tsends file to host if you have access to it\n", argv[0]);
      exit(1);
  }

  file = argv[1];
  host = argv[2];

  if(access(argv[1], R_OK) == 0) {
      int fd;
      int ffd;
      int rc;
      struct sockaddr_in sin;
      char buffer[4096];

      printf("Connecting to %s:18211 .. ", host); fflush(stdout);

      fd = socket(AF_INET, SOCK_STREAM, 0);

      memset(&sin, 0, sizeof(struct sockaddr_in));
      sin.sin_family = AF_INET;
      sin.sin_addr.s_addr = inet_addr(host);
      sin.sin_port = htons(18211);

      if(connect(fd, (void *)&sin, sizeof(struct sockaddr_in)) == -1) {
          printf("Unable to connect to host %s\n", host);
          exit(EXIT_FAILURE);
      }

#define HITHERE ".oO Oo.\n"
      if(write(fd, HITHERE, strlen(HITHERE)) == -1) {
          printf("Unable to write banner to host %s\n", host);
          exit(EXIT_FAILURE);
      }
#undef HITHERE

      printf("Connected!\nSending file .. "); fflush(stdout);

      ffd = open(file, O_RDONLY);
      if(ffd == -1) {
          printf("Damn. Unable to open file\n");
          exit(EXIT_FAILURE);
      }

      rc = read(ffd, buffer, sizeof(buffer));
      if(rc == -1) {
          printf("Unable to read from file: %s\n", strerror(errno));
          exit(EXIT_FAILURE);
      }

      write(fd, buffer, rc);

      printf("wrote file!\n");

  } else {
      printf("You don't have access to %s\n", file);
  }
}
```

这是一种叫文件访问竞态条件的漏洞.维基百科里面介绍的很详细了
[Time_of_check_to_time_of_use](https://en.wikipedia.org/wiki/Time_of_check_to_time_of_use).
大体利用是这用的。先大体看下代码
首先通过access 验证是否有文件读取权限`if(access(argv[1], R_OK) == 0)`。前面有说到`suid`会在执行的时候暂时性拥有文件拥有者的权限。这个在底层代码里面体现为`euid`，即`有限的uid`，比如我当前用户是`level10`,uid为`1011`，那执行正常的程序的时候我们`euid=uid=1011`，但是在有`suid`的程序中，`euid=文件拥有者的uid=flag10的uid=989`。一般的判断都是通过euid。
但是这里有个意外，就是`access`是通过`uid`而不是`euid`。所以这里，执行者为`level10`，没有执行的权限，验证不通过。
维基百科上给出的利用条件是利用软连接
代码是这样的
```
if(access(文件名, R_OK) == 0) {
        ...
	ffd = open(file, O_RDONLY);
	...
	rc = read(ffd, buffer, sizeof(buffer));	
}
```
我们用个软连接，让access之前lntoken 链接到 faketoken，这里的话，level10对 faketoken具有读取权限，验证通过。。接下来在open之前。把
lntoken 链接到token，这个时候由于是suid，而且open 验证的是euid。所以读取成功。我们想实现的伪代码如下
```
ln -sf faketoken lntoken
if(access(文件名, R_OK) == 0) { => 验证通过
      ln -sf realtoken lntoken => 已经指向正确的token 了
        ...
	ffd = open(file, O_RDONLY);
	...
	rc = read(ffd, buffer, sizeof(buffer));	
}
```
这种现象在单线程下几乎不可能，控制到那么精准的时间更换软连接。
但是现在的Linux几乎是多线程的，就可以条件竞争。
具体利用如下
新建fakeotkoen
![image.png](https://upload-images.jianshu.io/upload_images/5443560-0f2d1200236ef762.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
新建个不断软连接的死循环，这里我用`-x` 方便看到具体过程
![image.png](https://upload-images.jianshu.io/upload_images/5443560-1a8cd7ab4c2f8ea4.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
![image.png](https://upload-images.jianshu.io/upload_images/5443560-09cf1de358ac6548.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
再看一个终端，不断执行程序
![image.png](https://upload-images.jianshu.io/upload_images/5443560-a4762cc935be3785.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)。

接收到真的token
![image.png](https://upload-images.jianshu.io/upload_images/5443560-c4689c881e588181.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
可以登录了
 
## 0x0C level11
>The /home/flag11/flag11 binary processes standard input and executes a shell command.
There are two ways of completing this level, you may wish to do both :-)

## 0x0D level12
>There is a backdoor process listening on port 50001.

源码
```LUA
local socket = require("socket")
local server = assert(socket.bind("127.0.0.1", 50001))

function hash(password)
  prog = io.popen("echo "..password.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end


while 1 do
  local client = server:accept()
  client:send("Password: ")
  client:settimeout(60)
  local line, err = client:receive()
  if not err then
      print("trying " .. line) -- log from where ;\
      local h = hash(line)

      if h ~= "4754a4f4bd5787accd33de887b9250a0691dd198" then
          client:send("Better luck next time\n");
      else
          client:send("Congrats, your token is 413**CARRIER LOST**\n")
      end

  end

  client:close()
end
```
看下这个程序，就是把你输入的密码经过hash后跟`4754a4f4bd5787accd33de887b9250a0691dd198`比较，如果一样，就
输出`Congrats, your token is 413**CARRIER LOST**`。这里面的hash是自定义的
```LUA
function hash(password)
  prog = io.popen("echo "..password.." | sha1sum", "r")
  data = prog:read("*all")
  prog:close()

  data = string.sub(data, 1, 40)

  return data
end

```
。问题就出再popen里面`prog = io.popen("echo "..password.." | sha1sum", "r")`。通过调用系统命令来获取`hash`的。这一步拼接字符串，造成任意命令执行。
所以我们构造`;id > /tmp/id`看看
![image.png](https://upload-images.jianshu.io/upload_images/5443560-bb28c87f585db5a0.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
是`flag12`的

## 0x0E level13
>There is a security check that prevents the program from continuing execution if the user invoking it does not match a specific user id.

```
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <string.h>

#define FAKEUID 1000

int main(int argc, char **argv, char **envp)
{
  int c;
  char token[256];

  if(getuid() != FAKEUID) {
      printf("Security failure detected. UID %d started us, we expect %d\n", getuid(), FAKEUID);
      printf("The system administrators will be notified of this violation\n");
      exit(EXIT_FAILURE);
  }

  // snip, sorry :)

  printf("your token is %s\n", token);
  
}
```
这是一道简单的ELF逆向题，我这里提供两种思路
第一种动态调试.我用的是IDA.
在IDA的`dbgsrv`文件夹底下将`linux_server`拷贝到Linux服务器上运行，
![image.png](https://upload-images.jianshu.io/upload_images/5443560-9763e2be88a4e633.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
，然后打开ida 。`Debugger` -> `run` -> `remote Linux debugger `
然后开始配置
![image.png](https://upload-images.jianshu.io/upload_images/5443560-76e63267a2c50648.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
`Application `输要调试程序在服务器上的绝对路径。
`Diresctory` 输所在的路径
`Host` 输服务器的IP
跟OD基本一样了，F2在main函数下个断点，然后单步调试
![image.png](https://upload-images.jianshu.io/upload_images/5443560-4f09ec4a8d99b13e.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
执行到`080484F9`处，
![image.png](https://upload-images.jianshu.io/upload_images/5443560-a48742e20d61da5d.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
这里面的判断正是`if(getuid() != FAKEUID) `这个判断，通过修改zf标志位改变执行流程。在服务器端输出token 的值用于登陆
![image.png](https://upload-images.jianshu.io/upload_images/5443560-298de17773e2bd71.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
第二种方法是通过IDA静态查看代码，手动计算token的值
利用F5插件，查看类C代码
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __uid_t v3; // eax
  int v4; // ecx
  int i; // [esp+28h] [ebp-110h]
  int v7; // [esp+2Ch] [ebp-10Ch]
  unsigned int v8; // [esp+12Ch] [ebp-Ch]

  v8 = __readgsdword(0x14u);
  if ( getuid() != 1000 )
  {
    v3 = getuid();
    printf("Security failure detected. UID %d started us, we expect %d\n", v3, 1000);
    puts("The system administrators will be notified of this violation");
    exit(1);
  }
  memset(&v7, 0, 0x100u);
  strcpy(&v7, "8mjomjh8wml;bwnh8jwbbnnwi;>;88?o;9ob");
  v4 = *(_DWORD *)";9ob";
  for ( i = 0; *((_BYTE *)&v7 + i); ++i )
    *((_BYTE *)&v7 + i) ^= 0x5Au;
  return printf("your token is %s\n", &v7);
}
```
关键在
```
  memset(&v7, 0, 0x100u);
  strcpy(&v7, "8mjomjh8wml;bwnh8jwbbnnwi;>;88?o;9ob");
  v4 = *(_DWORD *)";9ob";
  for ( i = 0; *((_BYTE *)&v7 + i); ++i )
    *((_BYTE *)&v7 + i) ^= 0x5Au;
  return printf("your token is %s\n", &v7);
```
这里面V7的值就是token 。我使用python 计算
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-06-07 19:13:48
# @Author  : daiker (daikersec@gmail.com)
# @Link    : http://daikersec.com
# @Version : $Id$

token = "8mjomjh8wml;bwnh8jwbbnnwi;>;88?o;9ob"
print ''.join([chr(ord(i)^0x5A) for i in token])

```
得到token ![image.png](https://upload-images.jianshu.io/upload_images/5443560-594ecec88edc3427.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x0F level14 
>This program resides in /home/flag14/flag14. It encrypts input and writes it to standard output. An encrypted token file is also in that home directory, decrypt it :)

![image.png](https://upload-images.jianshu.io/upload_images/5443560-f39225877ed23dc8.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
是个加密程序，利用IDA来看下加密算法
```


int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  bool v3; // cf
  bool v4; // zf
  signed int v5; // ecx
  const char *v6; // esi
  _BYTE *v7; // edi
  int v8; // [esp+2Ch] [ebp-5Ch]
  signed int i; // [esp+30h] [ebp-58h]
  signed int v10; // [esp+34h] [ebp-54h]
  char buf[64]; // [esp+3Ch] [ebp-4Ch]
  unsigned int v12; // [esp+7Ch] [ebp-Ch]

  v12 = __readgsdword(0x14u);
  v8 = 0;
  if ( argc <= 1 )
    goto LABEL_17;
  v3 = __CFADD__(argv, 4);
  v4 = argv + 1 == 0;
  v5 = 3;
  v6 = argv[1];
  v7 = &unk_8048660;
  do
  {
    if ( !v5 )
      break;
    v3 = (const unsigned __int8)*v6 < *v7;
    v4 = *v6++ == *v7++;
    --v5;
  }
  while ( v4 );
  if ( (!v3 && !v4) != v3 )
  {
LABEL_17:
    printf("%s\n\t-e\tEncrypt input\n", *argv);
    exit(1);
  }
  while ( 1 )
  {
    v10 = read(0, buf, 0x40u);
    if ( v10 <= 0 )
      break;
    for ( i = 0; i < v10; ++i )
      buf[i] += v8++;
    if ( write(1, buf, v10) <= 0 )
      exit(0);
  }
  exit(0);
}

```

核心加密在

```
while ( 1 )
  {
    v10 = read(0, buf, 0x40u);
    if ( v10 <= 0 )
      break;
    for ( i = 0; i < v10; ++i )
      buf[i] += v8++;
    if ( write(1, buf, v10) <= 0 )
      exit(0);
  }
```

就是将每个字节的ASCII加上0,1,2,3这样，用python 写个解密算法

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Date    : 2018-06-07 19:53:26
# @Author  : daiker (daikersec@gmail.com)
# @Link    : http://daikersec.com
# @Version : $Id$

with open("token","rb") as f:
	order = 0
	token = ""
	while True:
		data = f.read(1)
		if not data:
			break
		token += chr(ord(data)-order)
		order += 1
print token
```
token为![image.png](https://upload-images.jianshu.io/upload_images/5443560-5b493df2ecca5a4b.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

## 0x10level15
>[strace](http://linux.die.net/man/1/strace) the binary at **/home/flag15/flag15** and see if you spot anything out of the ordinary.You may wish to [review](http://www.google.com.au/search?q=compile%20shared%20library%20linux) how to “compile a shared library in linux” and how the libraries are loaded and processed by reviewing the **dlopen** manpage in depth.
Clean up after yourself :)

## 0x11 level16 
>There is a perl script running on port 1616.

源码
```perl
#!/usr/bin/env perl

use CGI qw{param};

print "Content-type: text/html\n\n";

sub login {
  $username = $_[0];
  $password = $_[1];

  $username =~ tr/a-z/A-Z/; # conver to uppercase
  $username =~ s/\s.*//;        # strip everything after a space

  @output = `egrep "^$username" /home/flag16/userdb.txt 2>&1`;
  foreach $line (@output) {
      ($usr, $pw) = split(/:/, $line);
  

      if($pw =~ $password) {
          return 1;
      }
  }

  return 0;
}

sub htmlz {
  print("<html><head><title>Login resuls</title></head><body>");
  if($_[0] == 1) {
      print("Your login was accepted<br/>");
  } else {
      print("Your login failed<br/>");
  }    
  print("Would you like a cookie?<br/><br/></body></html>\n");
}

htmlz(login(param("username"), param("password")));
```





























