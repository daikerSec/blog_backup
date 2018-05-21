---
title: Linuxv0.11源码分析之引导启动程序一
tags:
  - Linux
  - 内核
category: [Linux,内核]
abbrlink: b309a0f3
date: 2018-03-19 13:16:28
---
## 0x00 大体流程
这篇文章所分析的代码是从开机到bios启动，到bios引导载入第一个引导扇区(bootsect.s)，到2到5个引导扇区(setup.s),到载入后面的240个扇区(head.s)的内容，
最后将程序的控制权交给`setup.s`
<!--more-->
## 0x01 bios做了什么
按下电源键的时候，CPU硬件逻辑设计为强行将CS的值置为0F000,IP的值置为0xFFF0,这样CS：IP就指向0xFFFF0这个地址位置。
而bios的入口地址就设计在这个位置。这个时候bios开始运行。bios会读取并检测显卡，内存等电脑硬件。
接下来bios会在内存中加载向量表和终端服务程序。此时内存的信息如下
```asm
0x00000-0x003FF 中断向量表(1kb)
0x00400-0x004FF BIOS数据区(256b)
....
57kb以后-xxxx(8kb)的终端服务程序
```
接下来bios会触发0x19中断
这个中断对应的中断服务程序的功能是将0号磁头对应盘面的0磁道1扇区的内容(共512个字节，就叫做”主引导记录”（Master boot record，缩写为MBR）)复制至内存`0x07C00`处

## 0x02 将随后的4个扇区加载进内存
从入口开始看
`boot/bootsect.s`
```asm
entry _start
_start:
	mov	ax,#BOOTSEG
	mov	ds,ax
	mov	ax,#INITSEG
	mov	es,ax
	mov	cx,#256
	sub	si,si
	sub	di,di
	rep
	movw !bootsec
```
这段代码是含义是将`BOOTSEG`后面512个字节移到`INITSEG`后面的512个字节
然后看下`BOOTSEG`和`INITSEG`的定义
```asm
BOOTSEG  = 0x07c0			! 启动扇区被BIOS加载的位置
INITSEG  = 0x9000			! 启动扇区将移动到的新位置
```
也就是说我们在前一步通过bios加载进内存的512字节，一开始会先把自己512字节内容由0x07c00复制到0x90000处
接下来
```asm
	jmpi	go,INITSEG !跳转到0x90000处继续执行
```
这里jmpi的格式是`jmpi ip,cs`。如果没有这一步，程序接下来会执行0x07C00为开始的那一段的go处。
但是这里跳转到0x90000开始的那一段内存的go处。跳转到复制完的地方执行。
接下来继续看
```asm
go:	mov	ax,cs
	mov	ds,ax
	mov	es,ax
	! put stack at 0x9ff00.
	mov	ss,ax
	mov	sp,#0xFF00		! arbitrary value >>512
```
前面已经改变了cs，现在对ds，es，sp的值进行设置
继续看
```asm
load_setup:
	mov	dx,#0x0000		! drive 0, head 0
	mov	cx,#0x0002		! sector 2, track 0
	mov	bx,#0x0200		! address = 512, in INITSEG
	mov	ax,#0x0200+SETUPLEN	! service 2, nr of sectors
	int	0x13			! read it
```
首先查下bios的0x13中断是什么意思
![BIOS中断表](https://upload-images.jianshu.io/upload_images/5443560-8e0e5dcf8d244507.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)
对应表格查阅，可以看出这几行代码的意思是把从第二个扇区开始的4个扇区(即setup.s，在boot/setup.s里面)读进内存es:bx处，
即0x90200处。前面说到第一个扇区的内存被复制到0x90000处，0x90200离0x90000有256字节，刚好是第一个扇区的长度。
也就是说第一个扇区和第二个扇区相邻。

```asm
jnc	ok_load_setup		! ok - continue
	mov	dx,#0x0000
	mov	ax,#0x0000		! reset the diskette
	int	0x13
	j	load_setup
```
这段代码是判断是否成功，没有成功的话，系统复位之后再重新读一次。


## 0x03 将后面的240个扇区加载进内存
接下来我们将第三批程序载入内存
从105行开始
```asm
! ok, we've written the message, now
! we want to load the system (at 0x10000)

	mov	ax,#SYSSEG
	mov	es,ax		! segment of 0x010000
	call	read_it
	call	kill_motor
```

这段代码的功能和载入setup.s一样，，只不过载入setup.s只有四个扇区，这段代码足足占了240个扇区。花的时间比较长，
为了防止用户以为机器故障，linus加了一个输出

```asm
	mov	ah,#0x03		! read cursor pos
	xor	bh,bh
	int	0x10
	
	mov	cx,#24
	mov	bx,#0x0007		! page 0, attribute 7 (normal)
	mov	bp,#msg1
	mov	ax,#0x1301		! write string, move cursor
	int	0x10
```

调用0x10中断输出`Loading system ...`
看下0x10中断的内容
![图片.png](https://upload-images.jianshu.io/upload_images/5443560-e41ee43275a295b8.png?imageMogr2/auto-orient/strip%7CimageView2/2/w/1240)

下面我们来具体看下这240个扇区怎么载入的

我们先看下`read_it`子模块

```asm
read_it:
	mov ax,es
	test ax,#0x0fff
die:	jne die			! 确保es必须是64kb
	xor bx,bx		!清空bx,使得bs可以被用作段内基址
rp_read:
	mov ax,es
	cmp ax,#ENDSEG		! have we loaded all yet?
	jb ok1_read
	ret
ok1_read:
	seg cs
	mov ax,sectors
	sub ax,sread
	mov cx,ax
	shl cx,#9
	add cx,bx
	jnc ok2_read
	je ok2_read
	xor ax,ax
	sub ax,bx
	shr ax,#9
ok2_read:
	call read_track
	mov cx,ax
	add ax,sread
	seg cs
	cmp ax,sectors
	jne ok3_read
	mov ax,#1
	sub ax,head
	jne ok4_read
	inc track
ok4_read:
	mov head,ax
	xor ax,ax
ok3_read:
	mov sread,ax
	shl cx,#9
	add bx,cx
	jnc rp_read
	mov ax,es
	add ax,#0x1000
	mov es,ax
	xor bx,bx
	jmp rp_read

read_track:
	push ax
	push bx
	push cx
	push dx
	mov dx,track
	mov cx,sread
	inc cx
	mov ch,dl
	mov dx,head
	mov dh,dl
	mov dl,#0
	and dx,#0x0100
	mov ah,#2
	int 0x13
	jc bad_rt
	pop dx
	pop cx
	pop bx
	pop ax
	ret
bad_rt:	mov ax,#0
	mov dx,#0
	int 0x13
	pop dx
	pop cx
	pop bx
	pop ax
	jmp read_track
```

接下来看`kill_motor`子模块

```asm
kill_motor:
	push dx
	mov dx,#0x3f2
	mov al,#0
	outb
	pop dx
	ret
```

## 0x04 确认下根设备号
## 0x05 将程序控制权转交给setup.s
```asm
SETUPSEG = 0x9020
```

```asm
! after that (everyting loaded), we jump to
! the setup-routine loaded directly after
! the bootblock:

	jmpi	0,SETUPSEG
```

前面说到0x13中断将第二个扇区到第五个扇区的内容(即setup.s的内容)加载到以0x90200处地址，现在跳转到那边，把控制权交给他





