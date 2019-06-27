package tcpraw

import (
	"log"
	"net"
	"testing"
)

//const testPortStream = "127.0.0.1:3456"
//const testPortPacket = "127.0.0.1:3457"

const testPortStream = "[::1]:3456"
const portServerPacket = ":3457"
const portRemotePacket = "127.0.0.1:3457"

func startTCPServer() net.Listener {
	l, err := net.Listen("tcp", testPortStream)
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				log.Println(err)
				return
			}

			go handleRequest(conn)
		}
	}()
	return l
}

func startTCPRawServer() *TCPConn {
	conn, err := Listen("tcp", portServerPacket)
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		for {
			buf := make([]byte, 128)
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				log.Println("server readfrom:", err)
				return
			}

			//echo
			n, err = conn.WriteTo(buf[:n], addr)
			if err != nil {
				log.Println("server writeTo:", err)
				return
			}
		}
	}()
	return conn
}

func handleRequest(conn net.Conn) {
	defer conn.Close()

	for {
		buf := make([]byte, 1024)
		size, err := conn.Read(buf)
		if err != nil {
			log.Println("handleRequest:", err)
			return
		}
		data := buf[:size]
		conn.Write(data)
	}
}

func TestDialTCPStream(t *testing.T) {
	l := startTCPServer()
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
	conn.Close()
	l.Close()
}

func TestDialToTCPPacket(t *testing.T) {
	s := startTCPRawServer()
	conn, err := Dial("tcp", portRemotePacket)
	if err != nil {
		t.Fatal(err)
	}

	addr, err := net.ResolveTCPAddr("tcp", portRemotePacket)
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
	conn.Close()
	s.Close()
}
