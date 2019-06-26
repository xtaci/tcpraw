package tcpraw

import (
	"log"
	"net"
	"testing"
)

const testPortStream = "127.0.0.1:3456"
const testPortPacket = "127.0.0.1:3457"

//const testPortStream = "[::1]:3456"
//const testPortPacket = "[::1]:3457"

func init() {
	l, err := net.Listen("tcp", testPortStream)
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

	conn, err := Listen("tcp", testPortPacket)
	if err != nil {
		log.Panicln(err)
	}
	log.Println("packet")

	go func() {
		for {
			buf := make([]byte, 128)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				log.Println(err)
				return
			}

			//echo
			n, err = conn.WriteTo(buf[:n], addr)
			if err != nil {
				log.Println(err)
				return
			}
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

func TestDialTCPStream(t *testing.T) {
	conn, err := Dial("tcp", testPortStream)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := net.ResolveTCPAddr("tcp", testPortStream)
	if err != nil {
		t.Fatal(err)
	}

	n, err := conn.WriteTo([]byte("abc"), addr)
	if err != nil {
		t.Fatal(n, err)
	}

	buf := make([]byte, 1500)
	if n, addr, err := conn.ReadFrom(buf); err != nil {
		t.Fatal(n, addr, err)
	} else {
		t.Log(string(buf[:n]), "from:", addr)
	}
}

func TestDialToTCPPacket(t *testing.T) {
	conn, err := Dial("tcp", testPortPacket)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := net.ResolveTCPAddr("tcp", testPortPacket)
	if err != nil {
		t.Fatal(err)
	}

	n, err := conn.WriteTo([]byte("abc"), addr)
	if err != nil {
		t.Fatal(n, err)
	}

	buf := make([]byte, 1500)
	if n, addr, err := conn.ReadFrom(buf); err != nil {
		t.Fatal(n, addr, err)
	} else {
		t.Log(string(buf[:n]), "from:", addr)
	}
}
