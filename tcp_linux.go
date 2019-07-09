// +build linux

package tcpraw

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/bpf"
)

var (
	errOpNotImplemented = errors.New("operation not implemented")
	expire              = time.Minute
)

// a message from NIC
type message struct {
	bts  []byte
	addr string
}

// a tcp flow information of a connection pair
type tcpFlow struct {
	writeReady   chan struct{}              // mark whether this flow is ready to WriteTo
	conn         *net.TCPConn               // the related system TCP connection of this flow
	handle       *afpacket.TPacket          // the handle to send packets
	seq          uint32                     // TCP sequence number
	ack          uint32                     // TCP acknowledge number
	linkLayer    gopacket.SerializableLayer // link layer header for tx
	networkLayer gopacket.SerializableLayer // network layer header for tx
	ts           time.Time                  // last packet incoming time
}

// TCPConn defines a TCP-packet oriented connection
type TCPConn struct {
	die     chan struct{}
	dieOnce sync.Once

	// the main golang sockets
	tcpconn  *net.TCPConn     // from net.Dial
	listener *net.TCPListener // from net.Listen

	// all handles for capturing on all related NICs
	handles []*afpacket.TPacket
	// packets captured from all related NICs will be delivered to this channel
	chMessage chan message

	// all TCP flows
	flowTable map[string]tcpFlow
	flowsLock sync.Mutex

	// iptables
	iptables *iptables.IPTables
	iprule   []string

	ip6tables *iptables.IPTables
	ip6rule   []string
}

// lockflow locks the flow table and apply function `f1` to the entry
func (conn *TCPConn) lockflow(addr net.Addr, f func(e *tcpFlow)) {
	key := addr.String()
	conn.flowsLock.Lock()
	e, ok := conn.flowTable[key]
	if !ok { // entry first visit
		e.writeReady = make(chan struct{})
		e.ts = time.Now()
	}
	f(&e)
	conn.flowTable[key] = e
	conn.flowsLock.Unlock()
}

// clean expired connections
func (conn *TCPConn) cleaner() {
	ticker := time.NewTicker(time.Minute)
	select {
	case <-conn.die:
		return
	case <-ticker.C:
		conn.flowsLock.Lock()
		for k, v := range conn.flowTable {
			if time.Now().Sub(v.ts) > expire {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
		}
		conn.flowsLock.Unlock()
	}
}

// captureFlow capture every inbound packets based on rules of BPF
func (conn *TCPConn) captureFlow(handle *afpacket.TPacket) {
	defer handle.Close()

	for {
		data, _, err := handle.ZeroCopyReadPacketData()
		if err != nil {
			return
		}

		// handle cannot be closed in a seperate goroutine,
		// if packets keep on flowing on this NIC
		// this goroutine will return eventually
		select {
		case <-conn.die:
			return
		default:
		}

		// try decoding as an Ethernet frame
		packet := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
		transport := packet.TransportLayer()
		if transport == nil { // retry as loopback frame
			packet = gopacket.NewPacket(data, layers.LinkTypeLoop, gopacket.DecodeOptions{NoCopy: true, Lazy: true})
			transport = packet.TransportLayer()
			if transport == nil {
				continue
			}
		}

		// try casting to TCP frame
		tcp, ok := transport.(*layers.TCP)
		if !ok {
			continue
		}

		// build transient address
		var src net.TCPAddr
		src.Port = int(tcp.SrcPort)
		var dst net.TCPAddr
		dst.Port = int(tcp.DstPort)

		// try IPv4 and IPv6
		if layer := packet.Layer(layers.LayerTypeIPv4); layer != nil {
			network := layer.(*layers.IPv4)
			src.IP = network.SrcIP
			dst.IP = network.DstIP
		} else if layer := packet.Layer(layers.LayerTypeIPv6); layer != nil {
			network := layer.(*layers.IPv6)
			src.IP = network.SrcIP
			dst.IP = network.DstIP
		}

		// compare IP and port, even though BPF has filtered some
		if conn.tcpconn != nil {
			raddr := conn.tcpconn.RemoteAddr().(*net.TCPAddr)
			if raddr.Port != src.Port { // from server
				continue
			}

			if !raddr.IP.Equal(src.IP) {
				continue
			}
		} else {
			laddr := conn.listener.Addr().(*net.TCPAddr)
			if laddr.Port != dst.Port { // to server
				continue
			}
			if laddr.IP != nil && !laddr.IP.IsUnspecified() {
				if !laddr.IP.Equal(dst.IP) {
					continue
				}
			}
		}

		// to keep track of TCP header
		conn.lockflow(&src, func(e *tcpFlow) {
			e.ts = time.Now()

			if tcp.ACK {
				e.seq = tcp.Ack
			}
			if tcp.PSH {
				e.ack = tcp.Seq + uint32(len(tcp.Payload))
			}
			if tcp.SYN { // for SYN packets, try initializing the flow entry once
				e.ack = tcp.Seq + 1
			}

			select {
			case <-e.writeReady:
			default:
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
					close(e.writeReady)
				}
			}
		})

		// deliver push data
		if tcp.PSH {
			payload := make([]byte, len(tcp.Payload))
			copy(payload, tcp.Payload)
			select {
			case conn.chMessage <- message{payload, src.String()}:
			case <-conn.die:
				return
			}
		}
	}
}

// ReadFrom implements the PacketConn ReadFrom method.
func (conn *TCPConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case <-conn.die:
		return 0, nil, io.EOF
	case packet := <-conn.chMessage:
		n = copy(p, packet.bts)
		addr, _ = net.ResolveTCPAddr("tcp", packet.addr)
		return n, addr, nil
	}
}

// WriteTo implements the PacketConn WriteTo method.
func (conn *TCPConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	var ready chan struct{}
	conn.lockflow(addr, func(e *tcpFlow) { ready = e.writeReady })

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
		buf.Clear()

		conn.lockflow(addr, func(e *tcpFlow) { e.seq += uint32(len(p)) })
		return len(p), nil
	}
}

// Close closes the connection.
func (conn *TCPConn) Close() error {
	var err error
	conn.dieOnce.Do(func() {
		// signal closing
		close(conn.die)

		// close all established tcp connections
		if conn.tcpconn != nil { // client
			setTTL(conn.tcpconn, 64)
			err = conn.tcpconn.Close()
		} else if conn.listener != nil {
			err = conn.listener.Close() // server
			conn.flowsLock.Lock()
			for k, v := range conn.flowTable {
				if v.conn != nil {
					setTTL(v.conn, 64)
					v.conn.Close()
				}
				delete(conn.flowTable, k)
			}
			conn.flowsLock.Unlock()
		}

		// delete iptable
		if conn.iptables != nil {
			conn.iptables.Delete("filter", "OUTPUT", conn.iprule...)
		}
		if conn.ip6tables != nil {
			conn.ip6tables.Delete("filter", "OUTPUT", conn.ip6rule...)
		}
	})
	return err
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
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ifaceName string
	for _, iface := range ifaces {
		if addrs, err := iface.Addrs(); err == nil {
			for _, addr := range addrs {
				if ipaddr, ok := addr.(*net.IPNet); ok {
					if ipaddr.IP.Equal(dummy.LocalAddr().(*net.UDPAddr).IP) {
						ifaceName = iface.Name
					}
				}
			}
		}
	}
	if ifaceName == "" {
		return nil, errors.New("cannot find correct interface")
	}

	// afpacket init
	handle, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.OptNumBlocks(1),
		afpacket.OptBlockSize(65536),
		afpacket.OptFrameSize(2048),
		afpacket.SocketRaw,
		afpacket.TPacketVersion2)
	if err != nil {
		return nil, err
	}

	// TCP local address reuses the same address from UDP
	laddr, err := net.ResolveTCPAddr(network, dummy.LocalAddr().String())
	if err != nil {
		return nil, err
	}
	dummy.Close()

	// apply filter
	// tcpdump -dd tcp and dst port 255
	filter := []bpf.RawInstruction{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 0, 4, 0x000086dd},
		{0x30, 0, 0, 0x00000014},
		{0x15, 0, 11, 0x00000006},
		{0x28, 0, 0, 0x00000038},
		{0x15, 8, 9, uint32(laddr.Port)},
		{0x15, 0, 8, 0x00000800},
		{0x30, 0, 0, 0x00000017},
		{0x15, 0, 6, 0x00000006},
		{0x28, 0, 0, 0x00000014},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x0000000e},
		{0x48, 0, 0, 0x00000010},
		{0x15, 0, 1, uint32(laddr.Port)},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000}}

	handle.SetBPF(filter)

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
	conn.handles = []*afpacket.TPacket{handle}
	conn.tcpconn = tcpconn
	conn.chMessage = make(chan message)
	go conn.captureFlow(handle)

	// record this flow
	conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) {
		e.conn = tcpconn
	})

	// iptables
	err = setTTL(tcpconn, 1)
	if err != nil {
		return nil, err
	}

	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "-d", raddr.IP.String(), "--dport", fmt.Sprint(raddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// discards data flow on tcp conn
	go io.Copy(ioutil.Discard, tcpconn)

	return conn, nil
}

// Listen acts like net.ListenTCP,
// and returns a single packet-oriented connection
func Listen(network, address string) (*TCPConn, error) {
	laddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var handles []*afpacket.TPacket
	if laddr.IP == nil || laddr.IP.IsUnspecified() { // if address is not specified, capture on all ifaces
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				var hasIP bool
				for _, addr := range addrs {
					if _, ok := addr.(*net.IPNet); ok {
						hasIP = true
						break
					}
				}

				// try open on all nics
				if hasIP {
					if handle, err := afpacket.NewTPacket(
						afpacket.OptInterface(iface.Name),
						afpacket.OptNumBlocks(1),
						afpacket.OptBlockSize(65536),
						afpacket.OptFrameSize(2048),
						afpacket.SocketRaw,
						afpacket.TPacketVersion2); err == nil {
						handles = append(handles, handle)
						// apply filter
						filter := []bpf.RawInstruction{
							{0x28, 0, 0, 0x0000000c},
							{0x15, 0, 4, 0x000086dd},
							{0x30, 0, 0, 0x00000014},
							{0x15, 0, 11, 0x00000006},
							{0x28, 0, 0, 0x00000038},
							{0x15, 8, 9, uint32(laddr.Port)},
							{0x15, 0, 8, 0x00000800},
							{0x30, 0, 0, 0x00000017},
							{0x15, 0, 6, 0x00000006},
							{0x28, 0, 0, 0x00000014},
							{0x45, 4, 0, 0x00001fff},
							{0xb1, 0, 0, 0x0000000e},
							{0x48, 0, 0, 0x00000010},
							{0x15, 0, 1, uint32(laddr.Port)},
							{0x6, 0, 0, 0x00040000},
							{0x6, 0, 0, 0x00000000}}

						handle.SetBPF(filter)
					} else {
						return nil, err
					}
				}
			}
		}
	} else {
		var ifaceName string
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					if ipaddr, ok := addr.(*net.IPNet); ok {
						if ipaddr.IP.Equal(laddr.IP) {
							ifaceName = iface.Name
						}
					}
				}
			}
		}
		if ifaceName == "" {
			return nil, errors.New("cannot find correct interface")
		}

		// afpacket init
		if handle, err := afpacket.NewTPacket(
			afpacket.OptInterface(ifaceName),
			afpacket.OptNumBlocks(1),
			afpacket.OptBlockSize(65536),
			afpacket.OptFrameSize(2048),
			afpacket.SocketRaw,
			afpacket.TPacketVersion2); err == nil {
			// apply filter
			filter := []bpf.RawInstruction{
				{0x28, 0, 0, 0x0000000c},
				{0x15, 0, 4, 0x000086dd},
				{0x30, 0, 0, 0x00000014},
				{0x15, 0, 11, 0x00000006},
				{0x28, 0, 0, 0x00000038},
				{0x15, 8, 9, uint32(laddr.Port)},
				{0x15, 0, 8, 0x00000800},
				{0x30, 0, 0, 0x00000017},
				{0x15, 0, 6, 0x00000006},
				{0x28, 0, 0, 0x00000014},
				{0x45, 4, 0, 0x00001fff},
				{0xb1, 0, 0, 0x0000000e},
				{0x48, 0, 0, 0x00000010},
				{0x15, 0, 1, uint32(laddr.Port)},
				{0x6, 0, 0, 0x00040000},
				{0x6, 0, 0, 0x00000000}}

			handle.SetBPF(filter)
			handles = []*afpacket.TPacket{handle}
		} else {
			return nil, err
		}
	}

	// start listening
	l, err := net.ListenTCP(network, laddr)
	if err != nil {
		return nil, err
	}

	// fields
	conn := new(TCPConn)
	conn.handles = handles
	conn.flowTable = make(map[string]tcpFlow)
	conn.die = make(chan struct{})
	conn.chMessage = make(chan message)
	conn.listener = l

	// iptables drop packets marked with TTL = 1
	// TODO: what if iptables is not available, the next hop will send back ICMP Time Exceeded,
	// is this still an acceptable behavior?
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4); err == nil {
		rule := []string{"-m", "ttl", "--ttl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.iprule = rule
					conn.iptables = ipt
				}
			}
		}
	}
	if ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv6); err == nil {
		rule := []string{"-m", "hl", "--hl-eq", "1", "-p", "tcp", "--sport", fmt.Sprint(laddr.Port), "-j", "DROP"}
		if exists, err := ipt.Exists("filter", "OUTPUT", rule...); err == nil {
			if !exists {
				if err = ipt.Append("filter", "OUTPUT", rule...); err == nil {
					conn.ip6rule = rule
					conn.ip6tables = ipt
				}
			}
		}
	}

	// start capturing
	for k := range handles {
		go conn.captureFlow(handles[k])
	}

	// discard everything in original connection
	go func() {
		for {
			tcpconn, err := l.AcceptTCP()
			if err != nil {
				return
			}

			// if we cannot set TTL = 1, the only thing reasonable is panic
			if err := setTTL(tcpconn, 1); err != nil {
				panic(err)
			}

			// record net.Conn
			conn.lockflow(tcpconn.RemoteAddr(), func(e *tcpFlow) {
				e.conn = tcpconn
			})

			go io.Copy(ioutil.Discard, tcpconn)
		}
	}()

	return conn, nil
}

// setTTL sets the Time-To-Live field on a given connection
func setTTL(c *net.TCPConn, ttl int) (err error) {
	var raw syscall.RawConn
	var addr *net.TCPAddr

	raw, err = c.SyscallConn()
	if err != nil {
		return err
	}
	addr = c.LocalAddr().(*net.TCPAddr)

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
