Frida-Apk-Unpack
====

基于Frida的脱壳工具
----

参考
----
dstmath的frida-unpack https://github.com/dstmath/frida-unpack

xiaokanghub的Frida-Android-unpack https://github.com/xiaokanghub/Frida-Android-unpack

对脚本功能做了优化，适配了更多平台，加强了对于各安卓版本的通用性

目前测试过Android4.4(貌似frida对Android4.4兼容并不好) Android5.1 Android6.0 Android7.1

0x0 frida环境搭建
----
frida环境搭建，参考frida官网：frida。

0x1 原理说明
----
利用frida hook libart.so中的OpenMemory或OpenCommon(Android N以后)方法，拿到内存中dex的地址，计算出dex文件的大小，从内存中将dex导出。

0x2 脚本用法
----
在手机上启动frida server端 执行 frida -U -f com.xxx.xxx -l dumpDex.js --no-pause 脱壳后的dex保存在/data/data/应用包名/目录下

0x3 适用环境
----
普通加固可以脱壳,对于类抽取等商业加固脱出的只是个空壳，需要做指令Dump以及Patch到脱出的Dex文件中,Android4.4测试某加密可以脱,某60只能脱出odex

0x4 参考链接
----
https://www.frida.re/docs/home/

https://github.com/dstmath/frida-unpack

https://github.com/xiaokanghub/Frida-Android-unpack
