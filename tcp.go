// +build !linux

package tcpraw

import "net"

func Dial(network, address string) (*net.UDPConn, error) {
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}

	return net.DialUDP("udp", nil, raddr)
}

func Listen(network, address string) (*net.UDPConn, error) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", laddr)
}
