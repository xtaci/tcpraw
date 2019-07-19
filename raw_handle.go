package tcpraw

import "net"

type rawHandle interface {
	ReadFromIP(b []byte) (int, *net.IPAddr, error)
	Write(b []byte) (int, error)
	WriteToIP(b []byte, addr *net.IPAddr) (int, error)
}
