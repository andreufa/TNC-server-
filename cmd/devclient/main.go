//go:build ignore

// devclient is a tiny manual test client for the TCP server.
//
// Usage:
//
//	go run ./cmd/devclient <device_id> <password> [message-to-send]
//
// It performs the handshake, prints the server reply, then:
//   - if a message is given, sends it once,
//   - and prints every broadcast message it receives until you Ctrl+C.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println("usage: go run ./cmd/devclient <device_id> <password> [message]")
		os.Exit(1)
	}
	id, pass := os.Args[1], os.Args[2]

	addr := os.Getenv("TCP_ADDR")
	if addr == "" {
		addr = "localhost:9000"
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		fmt.Println("dial:", err)
		os.Exit(1)
	}
	defer conn.Close()

	hs, _ := json.Marshal(map[string]string{"device_id": id, "password": pass})
	conn.Write(append(hs, '\n'))

	r := bufio.NewReader(conn)
	reply, _ := r.ReadString('\n')
	fmt.Print("handshake reply: ", reply)

	if len(os.Args) >= 4 {
		go func() {
			time.Sleep(500 * time.Millisecond)
			msg := os.Args[3]
			conn.Write(append([]byte(msg), '\n'))
			fmt.Println("sent:", msg)
		}()
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			fmt.Println("connection closed:", err)
			return
		}
		fmt.Print("recv: ", line)
	}
}
