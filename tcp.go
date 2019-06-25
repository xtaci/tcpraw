package tcpraw

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	bts  []byte
	addr net.Addr
}

// TCPConn defines a TCP-packet oriented connection
type TCPConn struct {
	ready    chan struct{}
	tcpconn  *net.TCPConn
	listener *net.TCPListener
	// gopacket
	handle       *pcap.Handle
	packetSource *gopacket.PacketSource
	chPacket     chan Packet                // incoming packets channel
	linkLayer    gopacket.SerializableLayer // link layer header
	networkLayer gopacket.SerializableLayer // network layer header

	// important TCP header information
	Seq uint32
	Ack uint32
}

// Dial connects to the remote TCP port
func Dial(network, address string) (*TCPConn, error) {
	// remote address resolve
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// create a dummy UDP socket, to get routing information
	dummy, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}

	// get iface name from the dummy connection, eg. eth0, lo0
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

	// pcap init
	handle, err := pcap.OpenLive(ifaceName, 65536, true, time.Second)
	if err != nil {
		return nil, err
	}

	// TCP local address reuses the same address from UDP
	laddr, err := net.ResolveTCPAddr(network, dummy.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dummy.Close()

	// apply filter for incoming data
	filter := fmt.Sprintf("tcp and dst host %v and dst port %v and src host %v and src port %v", laddr.IP, laddr.Port, raddr.IP, raddr.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}

	// create an established tcp connection
	// will hack this tcp connection for packet transmission
	tcpconn, err := net.DialTCP(network, laddr, raddr)
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(TCPConn)
	conn.ready = make(chan struct{})
	conn.handle = handle
	conn.tcpconn = tcpconn
	conn.startCapture(gopacket.NewPacketSource(handle, handle.LinkType()))

	// discards data flow on tcp conn, to keep the window slides
	go io.Copy(ioutil.Discard, tcpconn)

	return conn, nil
}

// packet startCapture
func (conn *TCPConn) startCapture(source *gopacket.PacketSource) {
	conn.chPacket = make(chan Packet, 128)
	conn.ready = make(chan struct{})

	go func() {
		var once sync.Once
		for packet := range source.Packets() {
			transport := packet.TransportLayer().(*layers.TCP)
			atomic.StoreUint32(&conn.Ack, transport.Seq)
			atomic.StoreUint32(&conn.Seq, transport.Ack)
			if transport.PSH {
				// retrieve IP
				var ip []byte
				if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
					network := layer.(*layers.IPv4)
					ip = make([]byte, len(network.SrcIP))
					copy(ip, network.SrcIP)
				} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
					network := layer.(*layers.IPv6)
					ip = make([]byte, len(network.SrcIP))
					copy(ip, network.SrcIP)
				}
				conn.chPacket <- Packet{transport.Payload, &net.TCPAddr{IP: ip, Port: int(transport.SrcPort)}}
			}

			once.Do(func() {
				// link layer
				if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
					ethLayer := layer.(*layers.Ethernet)
					conn.linkLayer = &layers.Ethernet{
						EthernetType: ethLayer.EthernetType,
						SrcMAC:       ethLayer.DstMAC,
						DstMAC:       ethLayer.SrcMAC,
					}
				} else if layer := packet.Layer(layers.LayerTypeLoopback); layer != nil {
					loopLayer := layer.(*layers.Loopback)
					conn.linkLayer = &layers.Loopback{Family: loopLayer.Family}
				}

				// network layer
				if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
					network := layer.(*layers.IPv4)
					conn.networkLayer = &layers.IPv4{
						SrcIP:    network.DstIP,
						DstIP:    network.SrcIP,
						Protocol: network.Protocol,
						Version:  network.Version,
						Id:       network.Id,
						Flags:    layers.IPv4DontFragment,
						TTL:      0x40,
					}
				} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
					network := layer.(*layers.IPv6)
					conn.networkLayer = &layers.IPv6{
						Version:    network.Version,
						NextHeader: network.NextHeader,
						SrcIP:      network.DstIP,
						DstIP:      network.SrcIP,
						HopLimit:   0x40,
					}
				}
				close(conn.ready)
			})
		}
	}()
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
	packet := <-conn.chPacket
	n = copy(p, packet.bts)
	return n, packet.addr, nil
}

// WriteTo writes a packet with payload p to addr.
// WriteTo can be made to time out and return
// an Error with Timeout() == true after a fixed time limit;
// see SetDeadline and SetWriteDeadline.
// On packet-oriented connections, write timeouts are rare.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	<-conn.ready
	tcpaddr, err := net.ResolveTCPAddr("tcp", addr.String())
	if err != nil {
		return 0, err
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	tcp := &layers.TCP{
		DstPort: layers.TCPPort(tcpaddr.Port),
		Window:  12580,
		Ack:     atomic.LoadUint32(&conn.Ack),
		Seq:     atomic.LoadUint32(&conn.Seq),
		PSH:     true,
		ACK:     true,
	}
	tcp.SetNetworkLayerForChecksum(conn.networkLayer.(gopacket.NetworkLayer))

	if conn.tcpconn != nil {
		tcp.SrcPort = layers.TCPPort(conn.tcpconn.LocalAddr().(*net.TCPAddr).Port)
	} else if conn.listener != nil {
		tcp.SrcPort = layers.TCPPort(conn.listener.Addr().(*net.TCPAddr).Port)
	}

	log.Printf("header: %+v", tcp)

	payload := gopacket.Payload(p)

	gopacket.SerializeLayers(buf, opts, conn.linkLayer, conn.networkLayer, tcp, payload)
	if err := conn.handle.WritePacketData(buf.Bytes()); err != nil {
		return 0, err
	}

	atomic.AddUint32(&conn.Seq, uint32(len(p)))
	return len(p), nil
}

// Close closes the connection.
// Any blocked ReadFrom or WriteTo operations will be unblocked and return errors.
func (conn *TCPConn) Close() error { return conn.tcpconn.Close() }

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
func (conn *TCPConn) SetDeadline(t time.Time) error { return conn.tcpconn.SetDeadline(t) }

// SetReadDeadline sets the deadline for future ReadFrom calls
// and any currently-blocked ReadFrom call.
// A zero value for t means ReadFrom will not time out.
func (conn *TCPConn) SetReadDeadline(t time.Time) error { return conn.tcpconn.SetReadDeadline(t) }

// SetWriteDeadline sets the deadline for future WriteTo calls
// and any currently-blocked WriteTo call.
// Even if write times out, it may return n > 0, indicating that
// some of the data was successfully written.
// A zero value for t means WriteTo will not time out.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error { return conn.tcpconn.SetWriteDeadline(t) }

// TCPListener returns a TCP-packet oriented listener
func Listen(network, address string) (*TCPConn, error) {
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// get iface name from the dummy connection, eg. eth0, lo0
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	var ifaceName string
	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if addr.IP.Equal(laddr.IP) {
				ifaceName = iface.Name
			}
		}
	}
	if ifaceName == "" {
		return nil, errors.New("cannot find correct interface")
	}

	// pcap init
	handle, err := pcap.OpenLive(ifaceName, 65536, true, time.Second)
	if err != nil {
		return nil, err
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	// apply filter for incoming data
	filter := fmt.Sprintf("tcp and dst host %v and dst port %v", laddr.IP, laddr.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, err
	}

	// fields
	conn := new(TCPConn)
	conn.handle = handle
	conn.listener = l
	conn.startCapture(gopacket.NewPacketSource(handle, handle.LinkType()))

	// discard everything in original connection
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}

			go io.Copy(ioutil.Discard, conn)
		}
	}()

	return conn, nil
}
