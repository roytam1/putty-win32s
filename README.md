# putty-win32s
A port of putty 0.76 to Windows 3.1+Win32s.

Maybe this may help close this bug:
https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/port-win32s.html

![putty-win32s](/assets/putty-about.png)
![putty-win32s](https://github.com/user-attachments/assets/3c6edeca-be3b-4f69-b1cd-98de0f004d96)

The whole windows sourcetree builds, and loads.

## Building
To build this, you need the following:
* OpenWatcom 2.0 beta under Windows

In Open Watcom Build Environment (i.e. a cmd window that has `owsetenv.bat` executed), `cd windows` and then `nmake -f Makefile.wc` to compile. (OpenWatcom package should have both `nmake.exe` and `rc.exe` included)

## Prerequistes
* Windows 3.1 (or 3.11 or 3.2 PRC version)
* Microsoft TCP/IP-32 version 3.11b or a compatible winsock 1.1 stack, for example, Trumpet Winsock
* Microsoft Win32s 1.30c (OLE-enabled one, might work in other versions, not tested)

## Running
* As the UNIX codepath for sessions saving/loading is used, you should set a HOME environment variable in AUTOEXEC.BAT
* If not, it defaults to C:\HOME
* run putty.exe

## What works
* the GUI apps, at least putty.exe, puttytel.exe and puttygen.exe
* limited UTF-8 support based on Active Code Page, for example CP1252 for en-US version of Windows, CP932 for ja-JP, CP950 for zh-TW, etc.

## What doesn't work
* Unicode that excceeds what Active Code Page (ACP) supports.
* pageant.exe.
* console applications.
  They'll load, and that's all, win32s doesn't support console applications.

As a replacement, there's an updated ssh2dos port here: https://github.com/AnttiTakala/SSH2DOS

Working scp2dos.exe/scp2d386.exe, sftpdos.exe/sftpd386.exe and ssh2dos.exe/ssh2d386.exe are now provided in releases.

The 386 variants are using the DOS32A extender which, in my experience, works correctly under win3.1.

Of course, they'll require a working wattcp environment, and either 2 NICs or something like ndis3pkt.
