package main

import (
	"net"
	"time"
	//	"crypto/rand"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	//	"time"
)

type sock5_client struct {
	id   int32
	conn net.Conn
}

//代理服务器集合
var proxy_list []net.Conn

//socket5客户端队列
//var sock5_list []*sock5_client
var sock5_list map[int32]*sock5_client = make(map[int32]*sock5_client)

func main() {
	if len(os.Args) < 2 {
		usage()
		return
	}
	sock5port, listenport := 1080, 9001
	connip := "127.0.0.1"
	connport := 9001

	switch os.Args[1] {
	case "-help":
		usage()
		break
	case "-listen":
		if len(os.Args) >= 4 {
			sock5port, _ = strconv.Atoi(os.Args[2])
			listenport, _ = strconv.Atoi(os.Args[3])
		}
		go socket5(sock5port)
		sslserver(listenport)
		break
	case "-connect":
		if len(os.Args) >= 4 {
			connip = os.Args[2]
			connport, _ = strconv.Atoi(os.Args[3])
		}
		connect(connip, connport)
		break
	}
}

//socket5数据处理
func handleSock5(conn net.Conn) {
	var headbuff [3]byte
	length, err := conn.Read(headbuff[0:3])
	if err != nil {
		fmt.Print("[-]sock5 read faild!\n")
		return
	}
	if length != 3 {
		conn.Close()
		fmt.Print("[-]no sock5 data!\n")
		return
	}
	//检查是不是socket5客户端
	if headbuff[0] != 0x05 || headbuff[1] != 1 || headbuff[2] != 0 {
		conn.Close()
		fmt.Print("[-]no sock5 data!\n")
		return
	}
	//应答
	//返回代理服务器可用
	length, err = conn.Write([]byte{0x05, 0x00})
	if err != nil {
		conn.Close()
		fmt.Print("[-]sock5 write 2 bytes faild!\n")
		return
	}
	var protocolbuff [4]byte
	var rep byte
	rep = 0x00
	length, err = conn.Read(protocolbuff[0:4])
	if err != nil || length < 1 {
		conn.Close()
		fmt.Print("[-]sock5 read faild!\n")
		return
	}
	//检查长度是否为sock5数据
	if length != 4 {
		conn.Close()
		fmt.Print("[-]no sock5 data!\n")
		return
	}
	//检查头是否为sock5数据
	if protocolbuff[0] != 0x05 || protocolbuff[2] != 0x00 {
		conn.Close()
		fmt.Print("[-]no sock5 data!\n")
		return
	}
	//检查是否是支持的协议（目前只支持tcp和udp）
	if protocolbuff[1] != 0x01 && protocolbuff[1] != 0x03 {
		conn.Close()
		fmt.Print("[-]only support tcp/udp\n")
		return
	}
	var remoteaddress string
	//获取需要代理的地址
	if protocolbuff[3] == 0x01 { //ipv4
		var ipbuff [4]byte
		length, err = conn.Read(ipbuff[0:4])
		if err != nil || length != 4 {
			conn.Close()
			fmt.Print("[-]sock5 read faild!\n")
			return
		}
		remoteaddress = fmt.Sprintf("%d.%d.%d.%d", ipbuff[0], ipbuff[1], ipbuff[2], ipbuff[3])
		fmt.Printf("[+]sock5 remote address %s\n", remoteaddress)
	} else if protocolbuff[3] == 0x03 { //域名
		//取得域名长度
		var domainlen [1]byte
		length, err = conn.Read(domainlen[0:1])
		if err != nil || length != 4 {
			conn.Close()
			fmt.Print("[-]sock5 read faild!\n")
			return
		}
		var domainlens int
		domainlens = int(domainlen[0])
		//创建相同长度的缓存区
		domainbuff := make([]byte, domainlens+1)
		//读取域名
		length, err = conn.Read(domainbuff[0:domainlens])
		if err != nil || length != domainlens {
			conn.Close()
			fmt.Print("[-]sock5 read faild!\n")
			return
		}
		fmt.Println("[+] domainname:", string(domainbuff))
		remoteaddress = string(domainbuff)
	} else {
		//不支持的类型
		rep = 0x08
		conn.Write([]byte{0x05, rep, 0x00, 0x01})
		conn.Close()
		return
	}
	//获取端口
	var portbuff [2]byte
	if rep == 0x00 {
		length, err = conn.Read(portbuff[0:2])
		if err != nil || length != 2 {
			conn.Close()
			fmt.Print("[-]sock5 read faild!\n")
			return
		}
	}
	//判断代理客户端是否可用
	if len(proxy_list) < 1 {
		conn.Write([]byte{0x05, rep, 0x00, 0x01})
		conn.Close()
	}

	//组包
	var proxy_id int32 = int32(len(proxy_list) + 1)
	sock5client := new(sock5_client)
	sock5client.id = proxy_id
	sock5client.conn = conn
	sock5_list[proxy_id] = sock5client

	//给proxy发送请求
	b_buf := bytes.NewBuffer([]byte{})
	b_buf.WriteByte(0x09)
	b_buf.WriteByte(0x01)
	binary.Write(b_buf, binary.BigEndian, &proxy_id)
	b_buf.WriteByte(0x01)
	b_buf.WriteByte(byte(len(remoteaddress)))
	b_buf.WriteString(remoteaddress)
	b_buf.WriteByte(portbuff[0])
	b_buf.WriteByte(portbuff[1])
	b_buf.WriteByte(0x08)

	length, err = proxy_list[0].Write(b_buf.Bytes())
	if err != nil || length != len(b_buf.Bytes()) {
		proxy_list[0].Close()
		conn.Close()
		fmt.Printf("[+]ssl write faild!\n")
		return
	}

	//可用应答
	rep = 0x00
	conn.Write([]byte{0x05, rep, 0x00, 0x01})
	conn.Close()
}

//创建socket5服务器
func socket5(port int) {
	server := fmt.Sprintf("0.0.0.0:%d", port)
	listen, err := net.Listen("tcp", server)
	if err != nil {
		fmt.Printf("[-]listen %s faild!\n", server)
		return
	}
	fmt.Printf("[+]listen %s ...\n", server)
	for {
		fmt.Print("[+]waiting for sock5 client...\n")
		conn, err := listen.Accept()
		if err != nil {
			fmt.Print("[-]ssl listen faild!\n ")
			continue
		}
		fmt.Printf("[+]sock5 %s connection...\n", conn.RemoteAddr())
		go handleSock5(conn)
	}
}

//ssl数据处理
func handleRecv(conn net.Conn) {
	var headbuff [3]byte
	len, err := conn.Read(headbuff[0:3])
	//判断客户端数据
	if err != nil || len != 3 {
		conn.Close()
		fmt.Printf("[+]ssl read faild!\n")
		return
	}
	//首包握手
	if headbuff[0] != 0x09 || headbuff[1] != 0x00 || headbuff[2] != 0x08 {
		conn.Close()
		fmt.Printf("[+]ssl data error!\n")
		return
	}
	//应答
	len, err = conn.Write(headbuff[0:3])
	if err != nil || len != 3 {
		conn.Close()
		fmt.Printf("[+]ssl write faild!\n")
		return
	}
	//握手成功，添加到代理列表
	proxy_list = append(proxy_list, conn)
	fmt.Printf("[+]ssl client %s checked!\n", conn.RemoteAddr())
	for {
		len, err = conn.Read(headbuff[0:1])
	}

}

//创建SSL服务器
func sslserver(port int) {
	cert, err := tls.LoadX509KeyPair("ca.crt", "ca.key")
	if err != nil {
		fmt.Print("[-]load certificate faild!\n")
		return
	}
	config := tls.Config{Certificates: []tls.Certificate{cert}}
	server := fmt.Sprintf("0.0.0.0:%d", port)
	listen, err := tls.Listen("tcp", server, &config)
	if err != nil {
		fmt.Print("[-]listen faild!\n")
		return
	}
	fmt.Printf("[+]listen %s ...\n", server)
	for {
		fmt.Print("[+]waiting for ssl client...\n")
		conn, err := listen.Accept()
		if err != nil {
			fmt.Print("[-]ssl accept faild!\n ")
			continue
		}
		fmt.Printf("[+]ssl %s connection...\n", conn.RemoteAddr())
		go handleRecv(conn)
	}
}

//客户端心跳包
func handleHB(conn net.Conn) {
	for {
		time.Sleep(time.Second * 10)
		len, err := conn.Write([]byte{0x09, 0x00, 0x08})
		if err != nil || len != 3 {
			fmt.Printf("[-]write faild!\n")
			conn.Close()
			break
		}
	}
}

//代理客户端
func connect(ip string, port int) {
	server := fmt.Sprintf("%s:%d", ip, port)
	fmt.Printf("[+]connect to %s...\n", server)
	config := tls.Config{InsecureSkipVerify: true, ServerName: ip}
	conn, err := tls.Dial("tcp", server, &config)
	if err != nil {
		fmt.Printf("[-]connect to %s faild!\n", server)
		return
	}
	fmt.Printf("[+]connect to %s done!\n", server)
	length, err := conn.Write([]byte{0x09, 0x00, 0x08})
	if err != nil || length != 3 {
		conn.Close()
		fmt.Printf("[-]write data faild!\n")
		return
	}
	var hbuff [3]byte
	length, err = conn.Read(hbuff[0:3])
	if err != nil || length != 3 {
		conn.Close()
		fmt.Printf("[-]read data faild!\n")
		return
	}
	if hbuff[0] != 0x09 || hbuff[1] != 0x00 || hbuff[2] != 0x08 {
		conn.Close()
		fmt.Printf("[+]ssl-server data error!\n")
		return
	}
	fmt.Printf("[+]author ssl-server done!\n")
	go handleHB(conn)
	for {
		var headbuff [3]byte
		var tailbuff [1]byte
		length, err = conn.Read(headbuff[0:2])
		if err != nil || length != 2 {
			conn.Close()
			fmt.Printf("[+]read data error!\n")
			break
		}
		//检查包头
		if headbuff[0] != 0x09 {
			fmt.Printf("[-]data error!\n")
			continue
		}
		//包类型
		if headbuff[1] == 0x00 { //心跳包
			length, err = conn.Read(tailbuff[0:1])
			if err != nil || length != 1 {
				conn.Close()
				fmt.Printf("[+]read data error!\n")
				break
			}
			//检查包尾
			if tailbuff[0] != 0x08 {
				fmt.Printf("[-]data error!\n")
				continue
			}
		} else if headbuff[1] == 0x01 { //请求包
			fmt.Printf("[debug]收到请求包\n")
			var proxy_id int32
			var proxy_id_buff []byte
			//读取proxy_)id
			length, err = conn.Read(proxy_id_buff[0:4])
			if err != nil || length != 4 {
				conn.Close()
				fmt.Printf("[+]read data error!\n")
				break
			}
			b_buf_proxy_id := bytes.NewBuffer(proxy_id_buff)
			binary.Read(b_buf_proxy_id, binary.BigEndian, &proxy_id)
			//读取协议类型和地址长度
			var proto_len []byte
			length, err = conn.Read(proto_len[0:2])
			if err != nil || length != 2 {
				conn.Close()
				fmt.Printf("[+]read data error!\n")
				break
			}

			//读取地址
			var address_len int = int(proto_len[1])
			var address_buff []byte
			length, err = conn.Read(address_buff[0:address_len])
			if err != nil || length != address_len {
				conn.Close()
				fmt.Printf("[+]read data error!\n")
				break
			}

			//读取端口
			var port_buff []byte
			length, err = conn.Read(port_buff[0:2])
			if err != nil || length != 2 {
				conn.Close()
				fmt.Printf("[+]read data error!\n")
				break
			}
			var port int16
			b_buf_port := bytes.NewBuffer(port_buff)
			binary.Write(b_buf_port, binary.BigEndian, &port)

			fmt.Sprintf("[debug]address:%s port:%d \n", string(address_buff), port)

		} else if headbuff[1] == 0x02 { //数据包

		} else { //错误的包
			fmt.Printf("[-]data error!\n")
			continue
		}
	}
}

//数据交换
func transmitData(sockfd1 net.Conn, sockfd2 net.Conn) {
	fmt.Printf("[+]start transmit (%s<->%s)\n", sockfd1.RemoteAddr(), sockfd2.RemoteAddr())

}

//使用说明
func usage() {
	fmt.Print("Usage:\n")
	fmt.Print("\t-listen  [port1] [port2]\n")
	fmt.Print("\t-connect [ip]    [port]\n")
	fmt.Print("\t-help\t\n")
}
