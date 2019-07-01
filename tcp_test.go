package tcpraw

import (
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

//const testPortStream = "127.0.0.1:3456"
//const testPortPacket = "127.0.0.1:3457"

const testPortStream = "[::1]:3456"
const portServerPacket = ":3457"
const portRemotePacket = "127.0.0.1:3457"

func init() {
	startTCPServer()
	startTCPRawServer()
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()
}

func startTCPServer() net.Listener {
	l, err := net.Listen("tcp", testPortStream)
	if err != nil {
		log.Panicln(err)
	}

	go func() {
		defer l.Close()
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
		defer conn.Close()
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
	conn, err := Dial("tcp", testPortStream)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

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
		log.Println(string(buf[:n]), "from:", addr)
	}
}

func TestDialToTCPPacket(t *testing.T) {
	conn, err := Dial("tcp", portRemotePacket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	addr, err := net.ResolveTCPAddr("tcp", portRemotePacket)
	if err != nil {
		t.Fatal(err)
	}

	n, err := conn.WriteTo([]byte("abc"), addr)
	if err != nil {
		t.Fatal(n, err)
	}
	log.Println("written")

	buf := make([]byte, 1500)
	log.Println("readfrom buf")
	if n, addr, err := conn.ReadFrom(buf); err != nil {
		log.Println(err)
		t.Fatal(n, addr, err)
	} else {
		log.Println(string(buf[:n]), "from:", addr)
	}

	log.Println("complete")
}

func BenchmarkEcho(b *testing.B) {
	conn, err := Dial("tcp", portRemotePacket)
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	addr, err := net.ResolveTCPAddr("tcp", portRemotePacket)
	if err != nil {
		b.Fatal(err)
	}

	buf := make([]byte, 1500)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		n, err := conn.WriteTo([]byte("abc"), addr)
		if err != nil {
			b.Fatal(n, err)
		}

		if n, addr, err := conn.ReadFrom(buf); err != nil {
			b.Fatal(n, addr, err)
		}
	}
}

func TestCompileBPF(t *testing.T) {
	filter := fmt.Sprintf("tcp and dst host 192.168.1.1 and dst port 255 and src host 192.168.1.1 and src port 256")
	log.Println(filter)
	if bpf, err := pcap.CompileBPFFilter(layers.LinkTypeIPv4, 1500, filter); err == nil {
		log.Printf("ipv4: %v", bpf)
	} else {
		t.Fatal(err)
	}
	filter = fmt.Sprintf("tcp and dst host ::1 and dst port 255 and src host ::2 and src port 256")
	if bpf, err := pcap.CompileBPFFilter(layers.LinkTypeIPv6, 1500, filter); err == nil {
		log.Printf("ipv6: %v", bpf)
	} else {
		t.Fatal(err)
	}

}
