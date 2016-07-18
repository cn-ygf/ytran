package main

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type proxy_data struct {
	id         int32    //proxy_id
	conn_sock5 net.Conn //socket5客户端连接
	conn_proxy net.Conn //SSL代理连接
}

type remote_data struct {
	proxy_id    int32    //proxy_id
	remote_conn net.Conn //远程连接
	server_conn net.Conn //ssl-server连接
}

//代理服务器集合
var proxy_list []net.Conn
var proxy_serv net.Conn

//代理客户端集合
var proxy_data_list map[int32]*proxy_data = make(map[int32]*proxy_data)

//远程连接集合
var remote_data_list map[int32]*remote_data = make(map[int32]*remote_data)

//proxy_data_list锁
var mutex sync.Mutex

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
		runtime.GOMAXPROCS(runtime.NumCPU())
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
		fmt.Print("[-]sock5 read headbuff faild!\n")
		return
	}
	if length != 3 {
		conn.Close()
		fmt.Print("[-]not sock5 data!\n")
		return
	}
	//检查是不是socket5客户端
	if headbuff[0] != 0x05 || headbuff[1] != 1 || headbuff[2] != 0 {
		conn.Close()
		fmt.Print("[-]not sock5 data!\n")
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
		fmt.Printf("[-]sock5 read protocolbuff faild!len:%d\n", length)
		fmt.Println(err)
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
			fmt.Print("[-]sock5 read ipbuff faild!\n")
			return
		}
		remoteaddress = fmt.Sprintf("%d.%d.%d.%d", ipbuff[0], ipbuff[1], ipbuff[2], ipbuff[3])
		fmt.Printf("[+]sock5 remote address %s\n", remoteaddress)
	} else if protocolbuff[3] == 0x03 { //域名
		//取得域名长度
		var domainlen [1]byte
		length, err = conn.Read(domainlen[0:1])
		if err != nil || length != 1 {
			conn.Close()
			fmt.Print("[-]sock5 read domainlen faild!\n")
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
			fmt.Print("[-]sock5 read domainbuff faild!\n")
			return
		}
		fmt.Println("[+]domainname:", string(domainbuff))
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
			fmt.Print("[-]sock5 read portbuff faild!\n")
			return
		}
	}
	//判断代理客户端是否可用
	/*if len(proxy_list) < 1 {
		conn.Write([]byte{0x05, rep, 0x00, 0x01})
		conn.Close()
	}*/

	//组包
	mutex.Lock()
	var proxy_id int32 = int32(len(proxy_data_list) + 1)
	proxydata := new(proxy_data)
	proxydata.id = proxy_id
	proxydata.conn_sock5 = conn
	//proxydata.conn_proxy = proxy_list[0]
	proxydata.conn_proxy = proxy_serv
	proxy_data_list[proxy_id] = proxydata
	mutex.Unlock()
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

	length, err = proxy_serv.Write(b_buf.Bytes())
	if err != nil || length != len(b_buf.Bytes()) {
		proxy_serv.Close()
		conn.Close()
		fmt.Printf("[+]ssl write faild!\n")
		return
	}

}

func handle_socket5_read(proxy_id int32) {
	proxydata, ok := proxy_data_list[proxy_id]
	if !ok {
		return
	}
	//读取socket5客户端的数据
	for {
		var buff []byte = make([]byte, 1024)
		length, err := proxydata.conn_sock5.Read(buff[0:1024])
		if err != nil {
			//读取socket5数据失败
			//通知ssl-client关闭对应的远程(remote)连接
			proxydata.conn_sock5.Close()
			sendclose(proxydata.conn_proxy, proxy_id)
			fmt.Printf("[-]sock5 read faild!\n")
			break
		}
		if length < 1 {
			continue
		}
		var len_16 int16 = int16(length)
		//组包发送给ssl客户端
		b_buf_send := bytes.NewBuffer([]byte{})
		b_buf_send.WriteByte(0x09)                            //包头
		b_buf_send.WriteByte(0x02)                            //数据类型是数据交换
		binary.Write(b_buf_send, binary.BigEndian, &proxy_id) //4byte proxy_id
		binary.Write(b_buf_send, binary.BigEndian, &len_16)   //2byte 数据包长度
		b_buf_send.Write(buff[0:length])                      //数据内容
		b_buf_send.WriteByte(0x08)                            //包尾

		//fmt.Println("[debug]", b_buf_send.Bytes())
		//发送
		length = completewrite(proxydata.conn_proxy, b_buf_send.Bytes())
		if length == -1 {
			proxydata.conn_proxy.Close()
			proxydata.conn_sock5.Close()
			fmt.Printf("[-]ssl write faild!\n")
			return
		}

	}
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
			fmt.Print("[-]socket5 accept faild!\n ")
			continue
		}
		fmt.Printf("[+]sock5 %s connection...\n", conn.RemoteAddr())
		go handleSock5(conn)
	}
}

//ssl数据处理
func handleRecv(conn net.Conn) {
	var hbbuff [3]byte
	length, err := conn.Read(hbbuff[0:3])
	//判断客户端数据
	if err != nil || length != 3 {
		conn.Close()
		fmt.Printf("[+]ssl read faild!\n")
		return
	}
	//首包握手
	if hbbuff[0] != 0x09 || hbbuff[1] != 0x00 || hbbuff[2] != 0x08 {
		conn.Close()
		fmt.Printf("[+]ssl data error!\n")
		return
	}
	//应答
	length, err = conn.Write(hbbuff[0:3])
	if err != nil || length != 3 {
		conn.Close()
		fmt.Printf("[+]ssl write faild!\n")
		return
	}
	//握手成功，添加到代理列表
	//proxy_list = append(proxy_list, conn)
	proxy_serv = conn
	fmt.Printf("[+]ssl client %s checked!\n", conn.RemoteAddr())
	for {
		//读取头和数据类型
		var headbuff [2]byte
		var tailbuff [1]byte
		length, err = conn.Read(headbuff[0:2])
		if err != nil || length != 2 {
			conn.Close()
			fmt.Printf("[-]ssl read faild!\n")
			break
		}
		//校验包头
		if headbuff[0] != 0x09 {
			conn.Close()
			fmt.Printf("[-]ssl headbuff error!\n")
			break
		}

		if headbuff[1] == 0x00 { //心跳包

		} else if headbuff[1] == 0x01 { //请求应答
			//读取proxyid + 是否成功  5 byte
			var request_buff []byte = make([]byte, 5)
			length, err = conn.Read(request_buff[0:5])
			if err != nil || length != 5 {
				conn.Close()
				fmt.Printf("[-]ssl read request_buff faild!\n")
				break
			}
			var proxy_id int32
			b_buf_request := bytes.NewBuffer(request_buff)
			binary.Read(b_buf_request, binary.BigEndian, &proxy_id)
			//检查列表里面proxy_id是否存在
			proxydata, ok := proxy_data_list[proxy_id]
			if ok {
				//判断远程是否连接成功
				if request_buff[4] == 0x00 { //远程连接未成功
					proxydata.conn_sock5.Close()
					fmt.Printf("[-]remote connect faild!\n")
				} else if request_buff[4] == 0x01 { //远程连接成功
					fmt.Printf("[+]remote connect done!\n")
					//读取ip地址 4byte
					var ip_buff []byte = make([]byte, 4)
					length, err = conn.Read(ip_buff[0:4])
					if err != nil || length != 4 {
						conn.Close()
						fmt.Printf("[-]ssl read ip_buff faild!\n")
						break
					}
					//端取端口 2 byte
					var port_buff []byte = make([]byte, 2)
					length, err = conn.Read(port_buff[0:2])
					if err != nil || length != 2 {
						conn.Close()
						fmt.Printf("[-]ssl read port_buff faild!\n")
						break
					}
					//fmt.Printf("[debug]%d.%d.%d.%d  %d %d\n", ip_buff[0], ip_buff[1], ip_buff[2], ip_buff[3], port_buff[0], port_buff[1])
					//向socket5客户端发送可以交换数据的包
					b_buf_send := bytes.NewBuffer([]byte{})
					b_buf_send.WriteByte(0x05)
					b_buf_send.WriteByte(0x00)
					b_buf_send.WriteByte(0x00)
					b_buf_send.WriteByte(0x01)
					b_buf_send.Write(ip_buff)
					b_buf_send.Write(port_buff)
					length, err = proxydata.conn_sock5.Write(b_buf_send.Bytes())
					if err != nil || length != len(b_buf_send.Bytes()) {
						proxydata.conn_sock5.Close()
						fmt.Printf("[-]sock5 write faild!\n")
					} else {
						//开始数据交换
						go handle_socket5_read(proxy_id)
					}
				}
			}
		} else if headbuff[1] == 0x02 { //数据交互协议
			//把收到的数据发送给socket5客户端
			//fmt.Printf("[debug]ssl-server收到数据交互\n")
			//读取proxy_id
			var proxy_id int32
			var proxy_id_buff []byte = make([]byte, 4)
			//读取proxy_id 4 byte
			length, err = conn.Read(proxy_id_buff[0:4])
			if err != nil || length != 4 {
				conn.Close()
				fmt.Printf("[+]read proxy_id error!\n")
				break
			}
			b_buf_proxy_id := bytes.NewBuffer(proxy_id_buff)
			binary.Read(b_buf_proxy_id, binary.BigEndian, &proxy_id)
			//fmt.Printf("[debug]proxy_id:%d\n", proxy_id)
			//读取数据长度 2 byte
			var data_len int16
			var data_len_buff []byte = make([]byte, 2)
			length, err = conn.Read(data_len_buff[0:2])
			if err != nil || length != 2 {
				conn.Close()
				fmt.Printf("[+]ssl read data_len_buff error!\n")
				break
			}
			b_buf_data_len := bytes.NewBuffer(data_len_buff)
			binary.Read(b_buf_data_len, binary.BigEndian, &data_len)
			//fmt.Printf("[debug]data_len:%d\n", data_len)
			//读取数据
			data_buff, errr := completeread(conn, int(data_len))
			if errr == -1 {
				conn.Close()
				fmt.Printf("[+]ssl read data_buff error!\n")
				break
			}
			//把数据发送给socket5客户端
			proxydata, ok := proxy_data_list[proxy_id]
			if ok {
				length = completewrite(proxydata.conn_sock5, data_buff)
				if length == -1 {
					//通知SSL客户端关闭远程连接
					proxydata.conn_sock5.Close()
					sendclose(proxydata.conn_proxy, proxydata.id)
					break
				}
			}
		} else if headbuff[1] == 0x03 { //关闭socket5客户端协议
			//fmt.Printf("[debug]收到关闭连接请求")
			var proxy_id int32
			var proxy_id_buff []byte = make([]byte, 4)
			//读取proxy_id 4 byte
			length, err = conn.Read(proxy_id_buff[0:4])
			if err != nil || length != 4 {
				conn.Close()
				fmt.Printf("[+]read proxy_id error!\n")
				break
			}
			b_buf_proxy_id := bytes.NewBuffer(proxy_id_buff)
			binary.Read(b_buf_proxy_id, binary.BigEndian, &proxy_id)
			//关闭socket5客户端
			proxydata, ok := proxy_data_list[proxy_id]
			if ok {
				proxydata.conn_sock5.Close()
			}
		} else { //未知协议

		}
		//读包尾
		length, err = conn.Read(tailbuff[0:1])
		if err != nil || length != 1 {
			conn.Close()
			fmt.Printf("[-]ssl read faild!\n")
			break
		}
		//fmt.Printf("[debug] tailbuff:%d\n", tailbuff[0])
		//校验包尾
		if tailbuff[0] != 0x08 {
			conn.Close()
			fmt.Printf("[-]ssl tailbuff error!\n")
			break
		}
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

//读取远程数据
func handleRemote(remote_id int32) {
	remotedata, ok := remote_data_list[remote_id]
	if ok {
		for {
			var buff []byte = make([]byte, 1024)
			length, err := remotedata.remote_conn.Read(buff[0:1024])
			if err != nil {
				//读取远程数据失败
				//通知ssl-server关闭对应的socket5客户端
				sendclose(remotedata.server_conn, remotedata.proxy_id)
				break
			}

			//组包发送数据给ssl-server
			var len16 int16 = int16(length)
			b_buf_send := bytes.NewBuffer([]byte{})
			b_buf_send.WriteByte(0x09)                                       //包头
			b_buf_send.WriteByte(0x02)                                       //数据类型
			binary.Write(b_buf_send, binary.BigEndian, &remotedata.proxy_id) //写入proxy_id
			binary.Write(b_buf_send, binary.BigEndian, &len16)               //写入数据长度
			b_buf_send.Write(buff[0:length])                                 //写入数据
			b_buf_send.WriteByte(0x08)                                       //写入包尾
			send_buff := b_buf_send.Bytes()
			//发送
			ret := completewrite(remotedata.server_conn, send_buff)
			if ret == -1 {
				//关闭远程连接
				remotedata.server_conn.Close()
				remotedata.remote_conn.Close()
				break
			}
			//fmt.Printf("[debug]发送了%d数据\n", b_buf_send.Len())
			//fmt.Printf("[debug]数据长度%d\n", length)
			//fmt.Println(send_buff)
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
		fmt.Printf("[-]read hbuff faild!\n")
		return
	}
	if hbuff[0] != 0x09 || hbuff[1] != 0x00 || hbuff[2] != 0x08 {
		conn.Close()
		fmt.Printf("[+]ssl-server data error!\n")
		return
	}
	fmt.Printf("[+]author ssl-server done!\n")
	//go handleHB(conn)
	for {
		//var headbuff []byte = make([]byte, 2)
		var tailbuff []byte = make([]byte, 1)
		headbuff, length := completeread(conn, 2)
		if length == -1 {
			conn.Close()
			fmt.Printf("[+]read headbuff error!%d\n", length)
			break
		}
		//length, err = conn.Read(headbuff)
		/*if err != nil || length != 2 {
			conn.Close()
			fmt.Printf("[+]read headbuff error!%d\n", length)
			break
		}*/
		//检查包头
		if headbuff[0] != 0x09 {
			fmt.Println("[-]headbuff data error!code:", headbuff)
			continue
		}
		//包类型
		if headbuff[1] == 0x00 { //心跳包
			length, err = conn.Read(tailbuff[0:1])
			if err != nil || length != 1 {
				conn.Close()
				fmt.Printf("[+]read tailbuff error!\n")
				break
			}
			//检查包尾
			if tailbuff[0] != 0x08 {
				fmt.Printf("[-]tailbuff error!\n")
				continue
			}
		} else if headbuff[1] == 0x01 { //请求包
			//fmt.Printf("[debug]收到请求包\n")
			var proxy_id int32
			var proxy_id_buff []byte = make([]byte, 4)
			//读取proxy_id
			length, err = conn.Read(proxy_id_buff[0:4])
			if err != nil || length != 4 {
				conn.Close()
				fmt.Printf("[+]read proxy_id error!\n")
				break
			}
			b_buf_proxy_id := bytes.NewBuffer(proxy_id_buff)
			binary.Read(b_buf_proxy_id, binary.BigEndian, &proxy_id)
			//读取协议类型和地址长度
			var proto_len []byte = make([]byte, 2)
			length, err = conn.Read(proto_len[0:2])
			if err != nil || length != 2 {
				conn.Close()
				fmt.Printf("[+]read proto_len error!\n")
				break
			}
			//读取地址
			var address_len int = int(proto_len[1])
			var address_buff []byte = make([]byte, address_len)
			length, err = conn.Read(address_buff[0:address_len])
			if err != nil || length != address_len {
				conn.Close()
				fmt.Printf("[+]read address error!\n")
				break
			}
			//读取端口
			var port_buff []byte = make([]byte, 2)
			length, err = conn.Read(port_buff[0:2])
			if err != nil || length != 2 {
				conn.Close()
				fmt.Printf("[+]read port_buff error!\n")
				break
			}
			var port int16
			b_buf_port := bytes.NewBuffer(port_buff)
			binary.Read(b_buf_port, binary.BigEndian, &port)
			//fmt.Printf("[debug]address:%s port:%d \n", string(address_buff), port)
			//读取校验包尾
			var tail_buff []byte = make([]byte, 1)
			length, err = conn.Read(tail_buff[0:1])
			if err != nil || length != 1 {
				conn.Close()
				fmt.Printf("[+]read tail_buff error!\n")
				break
			}
			if tail_buff[0] != 0x08 {
				conn.Close()
				fmt.Printf("[-]tail_buff error!\n")
				break
			}

			//这里需要改成异步连接

			//连接需要代理的服务器
			remote_conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", string(address_buff), port), time.Second*10)
			if err != nil {
				//通知SSL-server 主机不可答
				b_send_buff := bytes.NewBuffer([]byte{})
				b_send_buff.WriteByte(0x09)
				b_send_buff.WriteByte(0x01)
				b_send_buff.Write(proxy_id_buff)
				b_send_buff.WriteByte(0x00)
				b_send_buff.WriteByte(0x08)
				length, err = conn.Write(b_send_buff.Bytes())
				if err != nil {
					conn.Close()
					fmt.Printf("[+]write faild!\n")
					break
				}
				continue
			}
			//通知SSL-server连接远程地址成功
			remote_address := remote_conn.RemoteAddr().String()
			remote_ip := strings.Split(remote_address, ":")[0]
			remote_ips := strings.Split(remote_ip, ".")
			b_send_buff := bytes.NewBuffer([]byte{})
			b_send_buff.WriteByte(0x09)
			b_send_buff.WriteByte(0x01)
			b_send_buff.Write(proxy_id_buff)
			b_send_buff.WriteByte(0x01)
			//写入ip
			for i := 0; i < len(remote_ips); i++ {
				ipint, _ := strconv.Atoi(remote_ips[i])
				ipbyte := byte(ipint)
				b_send_buff.WriteByte(ipbyte)
			}
			//写入端口
			b_send_buff.Write(port_buff)
			//包尾
			b_send_buff.WriteByte(0x08)
			length, err = conn.Write(b_send_buff.Bytes())
			if err != nil {
				conn.Close()
				fmt.Printf("[+]write faild!\n")
				break
			}

			//绑定数据交换
			remotedata := new(remote_data)
			remotedata.proxy_id = proxy_id
			remotedata.remote_conn = remote_conn
			remotedata.server_conn = conn
			remote_data_list[proxy_id] = remotedata

			//读取远程数据
			go handleRemote(proxy_id)
		} else if headbuff[1] == 0x02 { //数据包
			//收到的数据包根据proxy_id找到远程列表发送
			var proxy_id int32
			var proxy_id_buff []byte = make([]byte, 4)
			//读取proxy_id 4 byte
			length, err = conn.Read(proxy_id_buff[0:4])
			if err != nil || length != 4 {
				conn.Close()
				fmt.Printf("[+]read proxy_id error!\n")
				break
			}
			b_buf_proxy_id := bytes.NewBuffer(proxy_id_buff)
			binary.Read(b_buf_proxy_id, binary.BigEndian, &proxy_id)
			//fmt.Printf("[debug]proxy_id:%d\n", proxy_id)
			//读取数据长度 2 byte
			var data_len int16
			var data_len_buff []byte = make([]byte, 2)
			length, err = conn.Read(data_len_buff[0:2])
			if err != nil || length != 2 {
				conn.Close()
				fmt.Printf("[+]read data_len_buff error!\n")
				break
			}
			b_buf_data_len := bytes.NewBuffer(data_len_buff)
			binary.Read(b_buf_data_len, binary.BigEndian, &data_len)
			//fmt.Printf("[debug]data_len:%d\n", data_len)
			//读取数据
			data_buff, errr := completeread(conn, int(data_len))
			if errr == -1 {
				conn.Close()
				fmt.Printf("[+]read data_buff error!\n")
				break
			}
			//读取包尾
			var tail_buff []byte = make([]byte, 1)
			length, err = conn.Read(tail_buff)
			if err != nil || length != 1 {
				conn.Close()
				fmt.Printf("[+]read tail_buff error!\n")
				break
			}
			if tail_buff[0] != 0x08 {
				conn.Close()
				fmt.Printf("[-]tail_buff error!%d\n", tail_buff[0])
				break
			}
			//把数据发送给远程数据
			//需要异步发送
			remotedata, ok := remote_data_list[proxy_id]
			if ok {
				length = completewrite(remotedata.remote_conn, data_buff)
				if length == -1 {
					//发送远程数据失败，通知ssl-server关闭对应的socket5
					fmt.Printf("[+]write remote_buff faild!\n")
					remotedata.remote_conn.Close()
					continue
				}
			} else {
				fmt.Printf("[-]not find remote_data_list:%d!\n", proxy_id)
			}

		} else if headbuff[1] == 0x03 { //关闭远程连接包
			//fmt.Printf("[debug]收到关闭连接请求\n")
			var proxy_id int32
			var proxy_id_buff []byte = make([]byte, 4)
			//读取proxy_id 4 byte
			length, err = conn.Read(proxy_id_buff[0:4])
			if err != nil || length != 4 {
				conn.Close()
				fmt.Printf("[+]read proxy_id error!\n")
				break
			}
			b_buf_proxy_id := bytes.NewBuffer(proxy_id_buff)
			binary.Read(b_buf_proxy_id, binary.BigEndian, &proxy_id)
			remotedata, ok := remote_data_list[proxy_id]
			if ok {
				//关闭远程数据连接
				remotedata.remote_conn.Close()
			}
			//读取包尾
			var tail_buff []byte = make([]byte, 1)
			length, err = conn.Read(tail_buff)
			if err != nil || length != 1 {
				conn.Close()
				fmt.Printf("[+]read tail_buff error!\n")
				break
			}
			if tail_buff[0] != 0x08 {
				conn.Close()
				fmt.Printf("[-]tail_buff error!%d\n", tail_buff[0])
				break
			}
		} else { //错误的包
			fmt.Printf("[-]data error!\n")
			continue
		}
	}
}

//完整读取
func completeread(conn net.Conn, size int) ([]byte, int) {
	buff := make([]byte, size)
	count := 0
	for {
		length, err := conn.Read(buff[count:size])
		if err != nil {
			//fmt.Println("[debug]read:", err)
			return nil, -1
		}
		count = count + length
		if count >= size {
			break
		}
	}
	return buff, 0
}

//发送关闭连接协议
func sendclose(conn net.Conn, proxy_id int32) int {
	//组包
	b_buf_send := bytes.NewBuffer([]byte{})
	b_buf_send.WriteByte(0x09)
	b_buf_send.WriteByte(0x03)
	//写入proxy_id
	binary.Write(b_buf_send, binary.BigEndian, &proxy_id)
	b_buf_send.WriteByte(0x08)
	err := completewrite(conn, b_buf_send.Bytes())
	return err
}

//完整发送
func completewrite(conn net.Conn, buff []byte) int {
	send_data_len := len(buff)
	count := 0
	for {
		length, err := conn.Write(buff[count:send_data_len])
		if err != nil {
			return -1
		}
		count = count + length
		if count >= send_data_len {
			break
		}
	}
	return 0
}

//数据交换
func transmitData(sockfd1 net.Conn, sockfd2 net.Conn) {
	fmt.Printf("[+]start transmit (%s<->%s)\n", sockfd1.RemoteAddr(), sockfd2.RemoteAddr())

}

//使用说明
func usage() {
	fmt.Printf("======================== HUC Packet Transmit Tool V1.00 =======================\n")
	fmt.Printf("=========== Code by YGF , Welcome to http://www.cnhonker.com ==========\n")
	fmt.Print("[Usage:]\n")
	fmt.Print("\t-listen  [port1] [port2]\n")
	fmt.Print("\t-connect [ip]    [port]\n")
	fmt.Print("\t-help\t\n")
}
