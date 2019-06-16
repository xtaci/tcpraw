package tcpraw

import (
	"io"
	"log"
	"math/rand"
	"net"
	"runtime"
	"sync/atomic"
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

	// seq
	seqnum uint32
}

func Dial(network, address string) (*TCPConn, error) {
	tcpconn := new(TCPConn)
	tcpconn.seqnum = rand.Uint32()
	// remote
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
		SeqNum:      atomic.AddUint32(&conn.seqnum, 1),
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
	/*
		if err := conn.ipconn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			return err
		}
		defer conn.ipconn.SetReadDeadline(time.Time{})
	*/

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

	// send ACK
	packet = TCPHeader{
		Source:      uint16(conn.localPort), // Random ephemeral port
		Destination: uint16(conn.remotePort),
		SeqNum:      atomic.AddUint32(&conn.seqnum, 1),
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

// ReadFrom reads a packet from the connection,
// copying the payload into p. It returns the number of
// bytes copied into p and the return address that
// was on the packet.
// It returns the number of bytes read (0 <= n <= len(p))
// and any error encountered. Callers should always process
// the n > 0 bytes returned before considering the error err.
// ReadFrom can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetReadDeadline.
func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	for {
		buf := make([]byte, 1500)
		if numRead, addr, err := conn.ipconn.ReadFromIP(buf); err == nil {
			buf = buf[:numRead]
			tcp := NewTCPHeader(buf)
			if parseIPv4(addr.IP.To4()) != conn.remoteIP || tcp.Source != conn.remotePort {
				log.Println("readfrom", numRead, tcp.Ctrl, addr, tcp.Source, tcp.Destination, conn.remotePort)
				continue
			}
			// Closed port gets RST, open port gets SYN ACK
			if tcp.HasFlag(TCPFlagPsh) {
				n := copy(buf, buf[tcp.DataOffset<<2:])
				return n, addr, nil
			}
		} else {
			return numRead, addr, err
		}
	}
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return 0, nil
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (conn *TCPConn) Close() error {
	return nil
}

// LocalAddr returns the local network address.
func (conn *TCPConn) LocalAddr() net.Addr {
	return nil
}

// SetDeadline sets the read and write deadlines associated
// with the connection. It is equivalent to calling both
// SetReadDeadline and SetWriteDeadline.
//
// A deadline is an absolute time after which I/O operations
// fail with a timeout (see type Error) instead of
// blocking. The deadline applies to all future and pending
// I/O, not just the immediately following call to ReadFrom or
// WriteTo. After a deadline has been exceeded, the connection
// can be refreshed by setting a deadline in the future.
//
// An idle timeout can be implemented by repeatedly extending
// the deadline after successful ReadFrom or WriteTo calls.
//
// A zero value for t means I/O operations will not time out.
func (conn *TCPConn) SetDeadline(t time.Time) error {
	return nil
}

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (conn *TCPConn) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error {
	return nil
}
