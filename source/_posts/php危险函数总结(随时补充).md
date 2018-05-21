---
title: PHP危险函数总结(随时补充)
tags:
  - ctf
  - Web
  - php
category: [漏洞挖掘,代码审计,php]
abbrlink: 1067b4de
date: 2017-07-09 23:44:34
---
### 1. 获取当前文件路径
- echo `dirname(__FILE__)` ;
- echo `getcwd()`;
<!--more-->
### 2. 获取同目录下的所有文件名称

- echo `var_dump(glob('./*'))`;
- `system("ls")/system("dir")/system-->可换成执行系统命令的函数`;

 ### 3. 读取某个文件的内容

- echo `file_get_contents("flag.php")`;
- echo `fgets(fopen("flag.php","r"))`;
- - echo `fgetss(fopen("flag.php","r"))`;
- `show_source("flag.php")`;
- echo `fread(fopen("flag.php","r"),filesize("flag.php"))`;
- echo `var_dump(file("flag.php"))`;
- `copy("flag.php","daiker.txt")`;
- `include 'php://filter/read=convert.base64-encode/resource=flag.php'`;
- `highlight_file("flag.php")`;
- readfile("flag.php");

### 4. 执行系统命令的函数

- system
- passthru
- exec
- pcntl_exec
- shell_exec
- popen
- proc_open

### 5. 命令执行函数

- `eval("phpinfo();");`
- `assert("phpinfo();");`
- `preg_replace("/test/e","phpinfo();","jutst test");` 
- `call_user_func("assert","eval('phpinfo();system(\'whoami\');')");`
- `call_user_func_array("assert",array("phpinfo();"));`
- `fun = create_function('', assert('phpinfo()'));$fun();`
- `array_map("assert",array("phpinfo();"));`
- `fpassthru(fopen("flag.php","r"));`

### 6. 反序列化

- `unserialize()`


### 7.xxe

- `simplexml_load_file()`

### 8.文件操作
-  文件读取下载
	- `file_get_content()`
	- `highlight_file()`
	- `fopen()`
	- `readfile()`
	- `fread()`
	- `file()`
	- `fgets()`
	- `show_source()`
	- `fpassthru`
- 文件删除
	- unlink()
