package tcpraw

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	errOpNotImplemented = errors.New("operation not implemented")
	source              = rand.NewSource(time.Now().UnixNano())
)

// message represent a incoming packet with address
type message struct {
	bts  []byte
	addr net.Addr
}

// tcp flow information for a connection pair
type tcpFlow struct {
	handle       *pcap.Handle  // used in WriteTo to WritePacketData
	ready        chan struct{} // mark whether the flow is ready to WriteTo
	seq          uint32
	ack          uint32
	linkLayer    gopacket.SerializableLayer // link layer header
	networkLayer gopacket.SerializableLayer // network layer header
	ts           time.Time                  // last packet incoming
}

// TCPConn defines a TCP-packet oriented connection
type TCPConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// the original connection
	tcpconn  *net.TCPConn
	listener *net.TCPListener
	// connections accepted from listener
	sysConns     map[string]net.Conn
	sysConnsLock sync.Mutex

	// gopacket
	handles      []*pcap.Handle
	packetSource *gopacket.PacketSource
	chMessage    chan message // incoming packets channel

	// important TCP header information
	flowTable map[string]tcpFlow
	flowsLock sync.Mutex
}

// deleteflow deletes the entry from the flow table
func (conn *TCPConn) deleteflow(addr net.Addr) {
	key := addr.String()
	conn.flowsLock.Lock()
	delete(conn.flowTable, key)
	conn.flowsLock.Unlock()
}

// lockflow locks the flow table and apply function f on the entry
func (conn *TCPConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()
	conn.flowsLock.Lock()
	e, ok := conn.flowTable[key]
	if !ok { // entry first visit
		e.ready = make(chan struct{})
	}
	f(&e)
	conn.flowTable[key] = e
	conn.flowsLock.Unlock()
}

// setTTL sets the Time-To-Live field on a given connection
func (conn *TCPConn) setTTL(x interface{}, ttl int) (err error) {
	var raw syscall.RawConn
	var addr *net.TCPAddr

	if l, ok := x.(*net.TCPListener); ok {
		raw, err = l.SyscallConn()
		if err != nil {
			return err
		}
		addr = l.Addr().(*net.TCPAddr)
	} else if c, ok := x.(*net.TCPConn); ok {
		raw, err = c.SyscallConn()
		if err != nil {
			return err
		}
		addr = c.LocalAddr().(*net.TCPAddr)
	}

	if addr.IP.To4() == nil {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_UNICAST_HOPS, ttl)
		})
	} else {
		raw.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})
	}
	return
}

// captureFlow capture each packets inbound based on rules of BPF
func (conn *TCPConn) captureFlow(handle *pcap.Handle) {
	source := gopacket.NewPacketSource(handle, handle.LinkType())

	go func() {
		for packet := range source.Packets() {
			transport := packet.TransportLayer().(*layers.TCP)

			// build address
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
			addr := &net.TCPAddr{IP: ip, Port: int(transport.SrcPort)}

			conn.lockflow(addr, func(e *tcpFlow) {
				e.ts = time.Now()
				e.seq = transport.Ack // update sequence number for every incoming packet
				if transport.SYN {    // for SYN packets, try initialize the flow entry once
					select {
					case <-e.ready:
					default:
						e.ack = transport.Seq + 1
						e.handle = handle

						// create link layer for WriteTo
						if layer := packet.Layer(layers.LayerTypeEthernet); layer != nil {
							ethLayer := layer.(*layers.Ethernet)
							e.linkLayer = &layers.Ethernet{
								EthernetType: ethLayer.EthernetType,
								SrcMAC:       ethLayer.DstMAC,
								DstMAC:       ethLayer.SrcMAC,
							}
						} else if layer := packet.Layer(layers.LayerTypeLoopback); layer != nil {
							loopLayer := layer.(*layers.Loopback)
							e.linkLayer = &layers.Loopback{Family: loopLayer.Family}
						}

						// create network layer for WriteTo
						if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
							network := layer.(*layers.IPv4)
							e.networkLayer = &layers.IPv4{
								SrcIP:    network.DstIP,
								DstIP:    network.SrcIP,
								Protocol: network.Protocol,
								Version:  network.Version,
								Id:       network.Id,
								Flags:    layers.IPv4DontFragment,
								TTL:      64,
							}
						} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
							network := layer.(*layers.IPv6)
							e.networkLayer = &layers.IPv6{
								Version:    network.Version,
								NextHeader: network.NextHeader,
								SrcIP:      network.DstIP,
								DstIP:      network.SrcIP,
								HopLimit:   64,
							}
						}

						// this tcp flow is ready to operate based on flow information
						if e.linkLayer != nil && e.networkLayer != nil {
							close(e.ready)
						}
					}
				} else if transport.PSH {
					// Normal data push:
					// increase properly the ack number for other peer,
					// the other peer will update it's local sequence with the ack
					e.ack += uint32(len(transport.Payload))
					select {
					case conn.chMessage <- message{transport.Payload, addr}:
					case <-conn.die:
						return
					}
				} else if transport.FIN || transport.RST {
					e.ack++
					conn.deleteflow(addr)
					conn.closePeer(addr)
				}
			})
		}
	}()
}

// ReadFrom implements the PacketConn ReadFrom method.
func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-conn.die:
		return 0, nil, io.EOF
	case packet := <-conn.chMessage:
		n = copy(p, packet.bts)
		return n, packet.addr, nil
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var ready chan struct{}
	conn.lockflow(addr, func(e *tcpFlow) { ready = e.ready })

	select {
	case <-conn.die:
		return 0, io.EOF
	case <-ready:
		tcpaddr, err := net.ResolveTCPAddr("tcp", addr.String())
		if err != nil {
			return 0, err
		}

		buf := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		// fetch flow
		var flow tcpFlow
		conn.lockflow(addr, func(e *tcpFlow) { flow = *e })

		var localAddr *net.TCPAddr
		if conn.tcpconn != nil {
			localAddr = conn.tcpconn.LocalAddr().(*net.TCPAddr)
		} else {
			localAddr = conn.listener.Addr().(*net.TCPAddr)
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(localAddr.Port),
			DstPort: layers.TCPPort(tcpaddr.Port),
			Window:  12580,
			Ack:     flow.ack,
			Seq:     flow.seq,
			PSH:     true,
			ACK:     true,
		}

		tcp.SetNetworkLayerForChecksum(flow.networkLayer.(gopacket.NetworkLayer))

		payload := gopacket.Payload(p)

		gopacket.SerializeLayers(buf, opts, flow.linkLayer, flow.networkLayer, tcp, payload)
		if err := flow.handle.WritePacketData(buf.Bytes()); err != nil {
			return 0, err
		}

		conn.lockflow(addr, func(e *tcpFlow) { e.seq += uint32(len(p)) })
		return len(p), nil
	}
}

// Close closes the connection.
func (conn *TCPConn) Close() error {
	var err error
	conn.dieOnce.Do(func() {
		close(conn.die)
		// stop capturing
		for k := range conn.handles {
			conn.handles[k].Close()
		}

		// close all socket connections
		if conn.tcpconn != nil {
			conn.setTTL(conn.tcpconn, 64) // recover ttl before close, so it can say goodbye
			err = conn.tcpconn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // close listener
			conn.sysConnsLock.Lock()
			for k := range conn.sysConns { // close all accepted conns
				conn.setTTL(conn.sysConns[k], 64)
				conn.sysConns[k].Close()
			}
			conn.sysConns = nil
			conn.sysConnsLock.Unlock()
		}
	})
	return err
}

// when a FIN or RST has arrived, trigger conn.Close on the original connection
// called from captureFlow
func (conn *TCPConn) closePeer(addr net.Addr) {
	if conn.tcpconn != nil {
		conn.setTTL(conn.tcpconn, 64)
		conn.tcpconn.Close()
	} else if conn.listener != nil {
		conn.sysConnsLock.Lock()
		if c, ok := conn.sysConns[addr.String()]; ok {
			conn.setTTL(c, 64)
			c.Close()
			delete(conn.sysConns, addr.String())
		}
		conn.sysConnsLock.Unlock()
	}
}

// LocalAddr returns the local network address.
func (conn *TCPConn) LocalAddr() net.Addr {
	if conn.tcpconn != nil {
		return conn.tcpconn.LocalAddr()
	} else if conn.listener != nil {
		return conn.listener.Addr()
	}
	return nil
}

// SetDeadline implements the Conn SetDeadline method.
func (conn *TCPConn) SetDeadline(t time.Time) error { return errOpNotImplemented }

// SetReadDeadline implements the Conn SetReadDeadline method.
func (conn *TCPConn) SetReadDeadline(t time.Time) error { return errOpNotImplemented }

// SetWriteDeadline implements the Conn SetWriteDeadline method.
func (conn *TCPConn) SetWriteDeadline(t time.Time) error { return errOpNotImplemented }

// Dial connects to the remote TCP port,
// and returns a single packet-oriented connection
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
	conn.die = make(chan struct{})
	conn.flowTable = make(map[string]tcpFlow)
	conn.handles = []*pcap.Handle{handle}
	conn.tcpconn = tcpconn
	conn.setTTL(tcpconn, 0) // prevent tcpconn from sending ACKs
	conn.chMessage = make(chan message)
	conn.captureFlow(handle)

	// discards data flow on tcp conn
	go func() {
		io.Copy(ioutil.Discard, tcpconn)
		tcpconn.Close()
	}()

	return conn, nil
}

// Listen acts like net.ListenTCP,
// and returns a single packet-oriented connection
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

	var handles []*pcap.Handle
	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on all ifaces
		for _, iface := range ifaces {
			if len(iface.Addresses) > 0 {
				// try open on all nics
				if handle, err := pcap.OpenLive(iface.Name, 65536, true, time.Second); err == nil {
					// apply filter
					filter := fmt.Sprintf("tcp and dst port %v", laddr.Port)
					if err := handle.SetBPFFilter(filter); err != nil {
						return nil, err
					}

					handles = append(handles, handle)
				} else {
					return nil, err
				}
			}
		}
	} else {
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

		// apply filter
		filter := fmt.Sprintf("tcp and dst host %v and dst port %v", laddr.IP, laddr.Port)
		if err := handle.SetBPFFilter(filter); err != nil {
			return nil, err
		}
		handles = []*pcap.Handle{handle}
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(TCPConn)
	conn.sysConns = make(map[string]net.Conn)
	conn.handles = handles
	conn.flowTable = make(map[string]tcpFlow)
	conn.die = make(chan struct{})
	conn.listener = l
	conn.setTTL(l, 0) // prevent tcpconn from sending ACKs
	conn.chMessage = make(chan message)

	for k := range handles {
		conn.captureFlow(handles[k])
	}

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := l.Accept()
			if err != nil {
				return
			}

			// record original connections for proper closing
			conn.sysConnsLock.Lock()
			conn.sysConns[tcpconn.LocalAddr().String()] = tcpconn
			conn.sysConnsLock.Unlock()
			go func() { io.Copy(ioutil.Discard, tcpconn) }()
		}
	}()

	return conn, nil
}
