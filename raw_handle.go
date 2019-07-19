package tcpraw

import "net"

type rawHandle interface {
	ReadFromIP(b []byte) (int, *net.IPAddr, error)
	Write(b []byte) (int, error)
	WriteToIP(b []byte, addr *net.IPAddr) (int, error)
	SetReadBuffer(bytes int) error
	SetWriteBuffer(bytes int) error
	Close() error
}
