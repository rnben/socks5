package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

/*
Auth
VER	本次请求的协议版本号，取固定值 0x05（表示socks 5）
NMETHODS 客户端支持的认证方式数量，可取值 1~255
METHODS	可用的认证方式列表
*/
func Auth(client net.Conn) (err error) {
	buf := make([]byte, 256)

	// 读取 VER 和 NMETHODS
	n, err := io.ReadFull(client, buf[:2])
	if n != 2 {
		return errors.New("reading header: " + err.Error())
	}

	ver, nMethods := int(buf[0]), int(buf[1])
	if ver != 5 {
		return errors.New("invalid version")
	}

	// 读取 METHODS 列表
	n, err = io.ReadFull(client, buf[:nMethods])
	if n != nMethods {
		return errors.New("reading methods: " + err.Error())
	}

	/*
		VER	也是0x05，对上 SOCKS 5 的暗号
		METHOD	选定的认证方式；其中 0x00 表示不需要认证，0x02 是用户名/密码认证，……
	*/
	n, err = client.Write([]byte{0x05, 0x00})
	if n != 2 || err != nil {
		return errors.New("write rsp err: " + err.Error())
	}

	return nil
}

/*
Connect
VER	0x05，老暗号了
CMD 连接方式，0x01=CONNECT, 0x02=BIND, 0x03=UDP ASSOCIATE
RSV 保留字段，现在没卵用
ATYP 地址类型，0x01=IPv4，0x03=域名，0x04=IPv6
DST.ADDR 目标地址，细节后面讲
DST.PORT 目标端口，2字节，网络字节序（network octec order）
*/
func Connect(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 256)

	n, err := io.ReadFull(client, buf[:4])
	if n != 4 {
		return nil, errors.New("read header: " + err.Error())
	}

	ver, cmd, _, atyp := buf[0], buf[1], buf[2], buf[3]
	if ver != 5 || cmd != 1 {
		return nil, errors.New("invalid ver/cmd")
	}

	// ADDR 的格式取决于 ATYP
	addr := ""
	switch atyp {
	case 1:
		n, err = io.ReadFull(client, buf[:4])
		if n != 4 {
			return nil, errors.New("invalid IPv4: " + err.Error())
		}
		addr = fmt.Sprintf("%d.%d.%d.%d", buf[0], buf[1], buf[2], buf[3])

	case 3:
		n, err = io.ReadFull(client, buf[:1])
		if n != 1 {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addrLen := int(buf[0])

		n, err = io.ReadFull(client, buf[:addrLen])
		if n != addrLen {
			return nil, errors.New("invalid hostname: " + err.Error())
		}
		addr = string(buf[:addrLen])

	case 4:
		return nil, errors.New("IPv6: no supported yet")

	default:
		return nil, errors.New("invalid atyp")
	}

	// 读取的 PORT 是一个 2 字节的无符号整数。协议里说，这里用了 “network octec order” 网络字节序(BigEndian)
	n, err = io.ReadFull(client, buf[:2])
	if n != 2 {
		return nil, errors.New("read port: " + err.Error())
	}
	port := binary.BigEndian.Uint16(buf[:2])

	// 创建一个到 dst 的连接
	destAddrPort := fmt.Sprintf("%s:%d", addr, port)
	dest, err := net.Dial("tcp", destAddrPort)
	if err != nil {
		return nil, errors.New("dial dst: " + err.Error())
	}

	/*告诉客户端已经准备好了
	VER 暗号，还是暗号！
	REP 状态码，0x00=成功，0x01=未知错误，……
	RSV 依然是没卵用的 RESERVED
	ATYP 地址类型
	BND.ADDR 服务器和DST创建连接用的地址
	BND.PORT 服务器和DST创建连接用的端口
	*/
	// BND.ADDR/PORT 本应填入 dest.LocalAddr()
	n, err = client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if err != nil {
		dest.Close()
		return nil, errors.New("write rsp: " + err.Error())
	}

	return dest, nil
}

// Forward 转发
func Forward(client, target net.Conn) {
	forward := func(src, dest net.Conn) {
		defer src.Close()
		defer dest.Close()
		io.Copy(src, dest)
	}
	go forward(client, target)
	go forward(target, client)
}