package main

import (
	"net"
	"fmt"
	"syscall"
//	"io"
)

func main() {
	var v syscall.Rlimit
	v.Cur = 1000000
	v.Max = 1000000
	syscall.Setrlimit(syscall.RLIMIT_NOFILE,&v)
 
	for i := 0; i < 10000; i++ {
		fmt.Printf("%d\n", i)
		conn, err := net.Dial("tcp", "[fe80::20c:29ff:fe88:a588]:2000")
		if err != nil {
			fmt.Printf("Dial failed: %v", err)
			return
		}
		defer conn.Close()
	}
	fmt.Scanf("\n")
	/*
	_, err = conn.Write([]byte("hello"))
	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)

	fmt.Printf("%s",string(buf))
	*/
}
