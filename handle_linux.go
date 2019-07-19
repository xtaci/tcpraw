// +build linux

package tcpraw

import "net"

func DialIP(network string, laddr, raddr *net.IPAddr) (rawHandle, error) {
	return net.DialIP(network, laddr, raddr)
}

func ListenIP(network string, laddr *net.IPAddr) (rawHandle, error) {
	return net.ListenIP(network, laddr)
}
