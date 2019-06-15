package tcpraw

import (
	"math/rand"
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

type TCPConn struct {
	tx    net.Conn
	rx    *ipv4.RawConn
	laddr *net.TCPAddr
	raddr *net.TCPAddr
}

func Dial(network, address string) (*TCPConn, error) {
	raddr, err := net.ResolveTCPAddr(network, address)
	if err != nil {
		return nil, err
	}

	// a fake conn to get ip and port
	fakeconn, err := net.Dial("udp", address)
	if err != nil {
		return nil, err
	}
	laddr, _ := net.ResolveTCPAddr(network, fakeconn.LocalAddr().String())
	fakeconn.Close()

	// rx conn
	rxconn, err := net.Dial("ip4:tcp", raddr.IP.String())
	if err != nil {
		return nil, err
	}

	// bpf filter the only connection
	filter := []bpf.RawInstruction{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 15, 0, 0x000086dd},
		{0x15, 0, 14, 0x00000800},
		{0x30, 0, 0, 0x00000017},
		{0x15, 0, 12, 0x00000006},
		{0x20, 0, 0, 0x0000001a},
		{0x15, 0, 10, parseIPv4(raddr.IP.To4())}, // src ip
		{0x28, 0, 0, 0x00000014},
		{0x45, 8, 0, 0x00001fff},
		{0xb1, 0, 0, 0x0000000e},
		{0x48, 0, 0, 0x0000000e},
		{0x15, 0, 5, uint32(raddr.Port)}, // src port
		{0x20, 0, 0, 0x0000001e},
		{0x15, 0, 3, parseIPv4(laddr.IP.To4())}, // dst ip
		{0x48, 0, 0, 0x00000010},
		{0x15, 0, 1, uint32(laddr.Port)}, // dst port
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	}

	rawconn, err := ipv4.NewRawConn(rxconn.(net.PacketConn))
	if err != nil {
		return nil, err
	}

	if err := rawconn.SetBPF(filter); err != nil {
		return nil, err
	}

	// tx conn
	txconn, err := net.Dial("ip4:tcp", raddr.IP.String())
	if err != nil {
		return nil, err
	}

	tcpconn := new(TCPConn)
	tcpconn.tx = txconn
	tcpconn.rx = rawconn
	tcpconn.laddr = laddr
	tcpconn.raddr = raddr
	if err := tcpconn.sendSyn(); err != nil {
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

func (conn *TCPConn) sendSyn() error {
	packet := TCPHeader{
		Source:      uint16(conn.laddr.Port), // Random ephemeral port
		Destination: uint16(conn.raddr.Port),
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
	packet.Checksum = Csum(data, conn.laddr.IP.To4(), conn.raddr.IP.To4())
	data = packet.Marshal()

	_, err := conn.tx.Write(data)
	if err != nil {
		return err
	}

	return nil
}
