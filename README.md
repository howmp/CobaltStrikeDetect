CobaltStrike是一款渗透测试神器，支持http/https、tcp、smb等多种通信方式。

在hvv防守方、应急响应等场景中，都有检测CobaltStrike的需求。

## 现有检测方案

### 使用特征码扫描

* <https://github.com/Apr4h/CobaltStrikeScan>
* <https://github.com/CCob/BeaconEye>
* <https://github.com/jas502n/cs_yara>

通常使用yara规则去匹配内存或者文件,但缺点如不支持3.x、只支持http/https的beacon等

### 内核检测方案

* [[2021]检测Cobalt Strike只使用40行代码](https://key08.com/index.php/2021/07/25/1260.html)

其技术原理是

1. 在内核通过PsSetLoadImageNotifyRoutine设置镜像加载通知回调，之后任何exe,dll的加载都会被检测。
1. 而CobaltStrike使用sRDI方案，shellcode会调用LoadLibrary来加载需要dll，此时获取堆栈回溯
1. 检测调用者的内存属性为是否为private，是否可写

但缺点是

1. 内核模块启动要先与CobaltStrike，如果已经运行则无法检测
1. 在客户业务环境中内核模块要保证稳定性兼容性，还要解决数字签名等问题

## CobaltStrike特征分析

鉴于以上两种方案各有缺点，CobaltStrike的特征到底是什么?

我认为有两个通用的特征

1. 对于http/https通信而言CobaltStrike均使用WinINet.dll来进行通信
1. 无论选择exe/dll/raw等格式，CobaltStrike内存均会sRDI

## 通过ETW记录WinINet日志

ETW可以记录WinINet的进程id、线程id、url、请求头、返回状态码、返回头等信息

在应急中，可以通过进程id、线程id、url进一步排查，进而阻断其网络和进程。

### 手动操作步骤

1. 打开事件查看器
1. 打开菜单 查看->显示分析和调试日志
1. 进入 应用程序和服务日志->Microsoft->Windows->WinINet(Microsoft-Windows-WinINet)
1. 右键启动 `Microsoft-Windows-WinINet/UsageLog` 日志

![wininetlog](https://guage.cool/cobaltstrike-detect/wininetlog.png)

### 工具

用C#写了个简单的工具WinINetLogger

![wininetlogger](https://guage.cool/cobaltstrike-detect/wininetlogger.png)

## 通过应用层的堆栈回溯判断sRDI和CobaltStrike

sRDI本身具有很强的隐蔽性，在内存中可以任意编码、加密。

但正如前文提到的`内核检测方案`中，其调用系统api时，调用者的内存属性有问题。

正常调用系统api时，调用者内存属性一般为IMAGE类型，并且不可写。

但也有例外如C#和V8等包含jit即时编译的代码。

此时就需要结合CobaltStrike自身的特征

1. http/https时，堆栈回溯只有两种情况
    1. 睡眠时： sRDI -> kernel32.dll!Sleep
    1. 通信时：sRDI -> WinINet.dll!xxxx
1. bindSMB时，堆栈回溯只有两种情况
    1. 监听管道时：sRDI -> kernel32!ConnectNamedPipe
    1. 读取数据时：sRDI -> kernel32!ReadFile
1. bindTCP时，堆栈回溯只有两种情况
    1. 监听端口时：sRDI -> ws2_32.dll!accept
    2. 接收数据时：sRDI -> ws2_32.dll!recv

分析调用堆栈时，如果这些api的调用者内存有问题，那么就可以确定是CobaltStrike

### 通过ProcessHacker插件检测CobaltStrike

![results](https://guage.cool/cobaltstrike-detect/results.png)

## 参考链接

* <https://github.com/Apr4h/CobaltStrikeScan>
* <https://github.com/CCob/BeaconEye>
* <https://github.com/jas502n/cs_yara>
* <https://medium.com/threat-hunters-forge/threat-hunting-with-etw-events-and-helk-part-1-installing-silketw-6eb74815e4a0>
* <https://key08.com/index.php/2021/07/25/1260.html>
