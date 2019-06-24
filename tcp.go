package tcpraw

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type TCPConn struct {
	fd      int
	ipconn  *net.IPConn
	tcpconn *net.TCPConn
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

	// packet capture
	pktsrc   *gopacket.PacketSource
	chPacket chan []byte

	// seq
	seqnum uint32
	// ack
	acknum uint32
}

func Dial(network, address string) (*TCPConn, error) {
	conn := new(TCPConn)

	// remote address resolve
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// udp dummy
	dummy, err := net.Dial("udp4", address)
	if err != nil {
		return nil, err
	}

	// get iface name from the dummy connection
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var ifaceName string
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if addr.IP.Equal(dummy.LocalAddr().(*net.UDPAddr).IP) {
				ifaceName = iface.Name
			}
		}
	}
	if ifaceName == "" {
		return nil, errors.New("cannot find correct interface")
	}

	handle, err := pcap.OpenLive(ifaceName, 65536, true, time.Millisecond)
	if err != nil {
		return nil, err
	}

	laddr, err := net.ResolveTCPAddr("tcp", dummy.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dummy.Close()

	// apply filter
	filter := "tcp and dst host " + laddr.IP.String() +
		" and dst port " + fmt.Sprint(laddr.Port) +
		" and src host " + raddr.IP.String() +
		" and src port " + fmt.Sprint(raddr.Port)
	log.Println(filter)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}

	// create an established tcp connection
	// will hack this tcp connection for packet transmission
	tcpconn, err := net.DialTCP("tcp", laddr, raddr)
	if err != nil {
		return nil, err
	}

	// a raw socket for sending
	ipconn, err := net.Dial("ip4:tcp", raddr.IP.String())
	if err != nil {
		return nil, err
	}
	conn.ipconn = ipconn.(*net.IPConn)

	// fields
	conn.tcpconn = tcpconn
	conn.remoteAddress = address
	conn.remotePort = uint16(raddr.Port)
	conn.remoteIP = parseIPv4(raddr.IP.To4())
	conn.bRemoteIP = make([]byte, 4)
	copy(conn.bRemoteIP, raddr.IP.To4())

	conn.localPort = uint16(laddr.Port)
	conn.localIP = parseIPv4(laddr.IP.To4())
	conn.bLocalIP = make([]byte, 4)
	copy(conn.bLocalIP, laddr.IP.To4())

	// discard data flow on tcp conn
	go conn.discard()
	conn.chPacket = conn.receiver(gopacket.NewPacketSource(handle, handle.LinkType()))

	return conn, nil
}

func parseIPv4(ip4 net.IP) uint32 {
	var ip uint32
	ip |= uint32(ip4[0]) << 24
	ip |= uint32(ip4[1]) << 16
	ip |= uint32(ip4[2]) << 8
	ip |= uint32(ip4[3])
	return ip
}

// dummy tcp reader to discard all data read from tcp conn
func (conn *TCPConn) discard() { io.Copy(ioutil.Discard, conn.tcpconn) }

// packet receiver
func (conn *TCPConn) receiver(source *gopacket.PacketSource) chan []byte {
	var wg sync.WaitGroup
	wg.Add(1)
	payloadChan := make(chan []byte, 128)

	go func() {
		var once sync.Once
		for packet := range source.Packets() {
			transport := packet.TransportLayer().(*layers.TCP)
			atomic.StoreUint32(&conn.acknum, transport.Seq)
			atomic.StoreUint32(&conn.seqnum, transport.Ack)
			once.Do(wg.Done)
		}
	}()

	wg.Wait()
	return payloadChan
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
				continue
			}
			// Closed port gets RST, open port gets SYN ACK
			if tcp.HasFlag(TCPFlagPsh) {
				n := copy(p, buf[tcp.DataOffset<<2:])
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
	// PSH
	packet := TCPHeader{
		Source:      uint16(conn.localPort),
		Destination: uint16(conn.remotePort),
		SeqNum:      atomic.LoadUint32(&conn.seqnum),
		AckNum:      atomic.LoadUint32(&conn.acknum),
		DataOffset:  5, // 4 bits
		Reserved:    0, // 3 bits
		ECN:         0, // 3 bits
		Ctrl:        TCPFlagPsh | TCPFlagAck,
		Window:      uint16(rand.Uint32()),
		Checksum:    0,
		Urgent:      0,
		Options:     []TCPOption{},
	}

	data := packet.Marshal()
	packet.Checksum = Csum(data, conn.bLocalIP, conn.bRemoteIP)
	data = packet.Marshal()

	buf := make([]byte, len(data)+len(p))
	copy(buf, data)
	copy(buf[len(data):], p)

	if _, err := conn.ipconn.Write(buf); err != nil {
		return 0, err
	}

	atomic.AddUint32(&conn.seqnum, uint32(len(p)))
	return len(p), nil
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (conn *TCPConn) Close() error {
	conn.tcpconn.Close()
	return conn.ipconn.Close()
}

// LocalAddr returns the local network address.
func (conn *TCPConn) LocalAddr() net.Addr {
	return conn.tcpconn.LocalAddr()
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
func (conn *TCPConn) SetDeadline(t time.Time) error { return conn.ipconn.SetDeadline(t) }

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (conn *TCPConn) SetReadDeadline(t time.Time) error { return conn.ipconn.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error { return conn.ipconn.SetWriteDeadline(t) }
