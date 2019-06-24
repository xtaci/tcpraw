package tcpraw

import (
	"log"
	"net"
	"testing"
)

const testPort = "127.0.0.1:3456"

func init() {
	l, err := net.Listen("tcp", testPort)
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Panicln(err)
			}

			go handleRequest(conn)
		}
	}()
}

func handleRequest(conn net.Conn) {
	log.Println("Accepted new connection.")
	defer conn.Close()
	defer log.Println("Closed connection.")

	for {
		buf := make([]byte, 1024)
		size, err := conn.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		data := buf[:size]
		conn.Write(data)
	}
}

func TestDial(t *testing.T) {
	conn, err := Dial("tcp", testPort)
	if err != nil {
		t.Fatal(err)
	}

	n, err := conn.WriteTo([]byte("a message"), nil)
	if err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 1500)
	n, addr, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(buf[:n]), "from:", addr)
}
