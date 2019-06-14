package tcpraw

import (
	"net"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"
)

type TCPConn struct {
	conn    net.Conn
	rawconn *ipv4.RawConn
}

func Dial4(address string) (*TCPConn, error) {
	addr, err := net.ResolveTCPAddr("tcp4", address)
	if err != nil {
		return nil, err
	}

	conn, err := net.Dial("ip4:tcp", addr.IP.String())
	if err != nil {
		return nil, err
	}

	var ip uint32
	ip4 := addr.IP.To4()
	ip |= uint32(ip4[0]) << 24
	ip |= uint32(ip4[1]) << 16
	ip |= uint32(ip4[2]) << 8
	ip |= uint32(ip4[3])

	// bpf
	filter := []bpf.RawInstruction{
		{0x28, 0, 0, 0x0000000c},
		{0x15, 11, 0, 0x000086dd},
		{0x15, 0, 10, 0x00000800},
		{0x30, 0, 0, 0x00000017},
		{0x15, 0, 8, 0x00000006},
		{0x20, 0, 0, 0x0000001e},
		{0x15, 0, 6, ip}, // ip
		{0x28, 0, 0, 0x00000014},
		{0x45, 4, 0, 0x00001fff},
		{0xb1, 0, 0, 0x0000000e},
		{0x48, 0, 0, 0x00000010},
		{0x15, 0, 1, uint32(addr.Port)}, // port
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	}

	rawconn, err := ipv4.NewRawConn(conn.(*net.IPConn))
	if err != nil {
		return nil, err
	}

	rawconn.SetBPF(filter)

	tcpconn := new(TCPConn)
	tcpconn.conn = conn
	tcpconn.rawconn = rawconn
	return tcpconn, nil
}
