package tcpraw

import (
	"io"
	"log"
	"math/rand"
	"net"
	"runtime"
	"syscall"
	"time"
)

type TCPConn struct {
	fd     int
	ipconn *net.IPConn
	//rx *net.IPConn

	// local address
	localPort uint16
	localIP   uint32
	bLocalIP  []byte

	// remote address
	remotePort    uint16
	remoteIP      uint32
	bRemoteIP     []byte
	remoteAddress string
}

func Dial(network, address string) (*TCPConn, error) {
	tcpconn := new(TCPConn)
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	tcpconn.remoteAddress = address
	tcpconn.remotePort = uint16(raddr.Port)
	tcpconn.remoteIP = parseIPv4(raddr.IP.To4())
	tcpconn.bRemoteIP = make([]byte, 4)
	copy(tcpconn.bRemoteIP, raddr.IP.To4())

	// outgoing addres and port hack
	fakeconn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}

	laddr, err := net.ResolveTCPAddr("tcp", fakeconn.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	tcpconn.localPort = uint16(laddr.Port)
	tcpconn.localIP = parseIPv4(laddr.IP.To4())
	tcpconn.bLocalIP = make([]byte, 4)
	copy(tcpconn.bLocalIP, laddr.IP.To4())
	fakeconn.Close()

	// bind to that address and port again
	fd, err := syscall.Socket(syscall.AF_INET, syscall.O_NONBLOCK|syscall.SOCK_STREAM, 0)
	if err != nil {
		return nil, err
	}
	addr := syscall.SockaddrInet4{Port: int(tcpconn.localPort)}
	copy(addr.Addr[:], tcpconn.bLocalIP)
	if err := syscall.Bind(fd, &addr); err != nil {
		return nil, err
	}
	tcpconn.fd = fd
	runtime.SetFinalizer(tcpconn, func(conn *TCPConn) {
		syscall.Close(conn.fd)
	})

	// connected raw ip socket
	ipconn, err := net.Dial("ip4:tcp", raddr.IP.String())
	if err != nil {
		return nil, err
	}
	tcpconn.ipconn = ipconn.(*net.IPConn)

	// handshake
	if err := tcpconn.handshake(); err != nil {
		return nil, err
	}

	return tcpconn, nil
}

func parseIPv4(ip4 net.IP) uint32 {
	var ip uint32
	ip |= uint32(ip4[0]) << 24
	ip |= uint32(ip4[1]) << 16
	ip |= uint32(ip4[2]) << 8
	ip |= uint32(ip4[3])
	return ip
}

func (conn *TCPConn) handshake() error {
	// send SYN
	packet := TCPHeader{
		Source:      uint16(conn.localPort), // Random ephemeral port
		Destination: uint16(conn.remotePort),
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  5,                     // 4 bits
		Reserved:    0,                     // 3 bits
		ECN:         0,                     // 3 bits
		Ctrl:        TCPFlagSyn,            // 6 bits (000010, SYN bit set)
		Window:      uint16(rand.Uint32()), // The amount of data that it is able to accept in bytes
		Checksum:    0,                     // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}

	data := packet.Marshal()
	packet.Checksum = Csum(data, conn.bLocalIP, conn.bRemoteIP)
	data = packet.Marshal()

	_, err := conn.ipconn.Write(data)
	if err != nil {
		return err
	}

	// receive SYN ACK
	if err := conn.ipconn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return err
	}

	for {
		buf := make([]byte, 1024)
		numRead, addr, err := conn.ipconn.ReadFromIP(buf)
		if err != nil {
			log.Fatalf("ReadFrom: %s\n", err)
		}

		tcp := NewTCPHeader(buf[:numRead])
		if parseIPv4(addr.IP.To4()) != conn.remoteIP || tcp.Source != conn.remotePort {
			continue
		}
		// Closed port gets RST, open port gets SYN ACK
		if tcp.HasFlag(TCPFlagRst) {
			return io.ErrClosedPipe
		} else if tcp.HasFlag(TCPFlagSyn) && tcp.HasFlag(TCPFlagAck) {
			return nil
		}
	}
	conn.ipconn.SetReadDeadline(time.Time{})

	// send ACK
	packet = TCPHeader{
		Source:      uint16(conn.localPort), // Random ephemeral port
		Destination: uint16(conn.remotePort),
		SeqNum:      rand.Uint32(),
		AckNum:      0,
		DataOffset:  5,                     // 4 bits
		Reserved:    0,                     // 3 bits
		ECN:         0,                     // 3 bits
		Ctrl:        TCPFlagAck,            // 6 bits (000010, SYN bit set)
		Window:      uint16(rand.Uint32()), // The amount of data that it is able to accept in bytes
		Checksum:    0,                     // Kernel will set this if it's 0
		Urgent:      0,
		Options:     []TCPOption{},
	}
	data = packet.Marshal()
	packet.Checksum = Csum(data, conn.bLocalIP, conn.bRemoteIP)
	data = packet.Marshal()
	_, err = conn.ipconn.Write(data)
	if err != nil {
		return err
	}
	return nil
}
