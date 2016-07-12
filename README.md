正在开发中...

SSL的反连socket5代理
使用场景：
目标机器在内网，能反连出来
需要一台公网机器
Usage:
	-listen	 [port1] [port2]
	-connect [ip]	 [port]
	-help
在公网机器使用-listen命令监听 port1=socket5端口 port2=ssl服务端口
在内网机器使用-connect命令连接ssl服务端口