SSL的反连socket5代理

使用场景：

目标机器在内网，能反连出来

需要一台公网机器

Usage:

        -listen  [port1] [port2]

        -connect [ip]    [port]

        -help

在公网机器使用-listen命令监听 port1=socket5端口 port2=ssl服务端口

在内网机器使用-connect命令连接ssl服务端口

~~~~{python}
$ ./ytran -listen 1080 9001
$ ./ytran -connect 8.8.8.8 9001
~~~~

浏览器 8.8.8.8:1080 socket5

使用golang编写，无第三方包

客户端与服务端连接使用SSL单连接通信

golang编译环境:http://pan.baidu.com/s/1hq1mrDM

go build ytran.go

可在linux、osx、windows等环境使用

编译出可执行文件可直接在目标机器上使用


下一个版本功能 

1、增加数据压缩

2、优化网络环境差的情景

3、增加端口转发功能

[GitHub https://github.com/cn-ygf/ytran](https://github.com/cn-ygf/ytran)
