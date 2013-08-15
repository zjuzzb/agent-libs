package main

import (
	"io"
	"log"
	"net"
	"syscall"
)

func main() {
	var v syscall.Rlimit
	v.Cur = 1000000
	v.Max = 1000000
	syscall.Setrlimit(syscall.RLIMIT_NOFILE,&v)
 
	// Listen on TCP port 2000 on all interfaces.
	l, err := net.Listen("tcp", "192.168.22.207:2000")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		// Wait for a connection.
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}
		// Handle the connection in a new goroutine.
		// The loop then returns to accepting, so that
		// multiple connections may be served concurrently.
		go func(c net.Conn) {
			// Echo all incoming data.
			io.Copy(c, c)
			// Shut down the connection.
			c.Close()
		}(conn)
	}
}
