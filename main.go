package main

import (
	"fmt"
	"net"
	"socks5/socks5"
)

func main() {
	server, err := net.Listen("tcp", ":1080")
	if err != nil {
		fmt.Printf("Listen failed: %v\n", err)
		return
	}

	for {
		client, err := server.Accept()
		if err != nil {
			fmt.Printf("Accept failed: %v", err)
			continue
		}
		go process(client)
	}
}

func process(client net.Conn) {
	if err := socks5.Auth(client); err != nil {
		fmt.Println("auth error:", err)
		client.Close()
		return
	}

	target, err := socks5.Connect(client)
	if err != nil {
		fmt.Println("connect error:", err)
		client.Close()
		return
	}

	socks5.Forward(client, target)
}
