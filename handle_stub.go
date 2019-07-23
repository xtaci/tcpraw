// +build !linux

package tcpraw

import (
	"errors"
	"net"
)

func DialIP(network string, laddr, raddr *net.IPAddr) (rawHandle, error) {
	return nil, errors.New("os not supported")
}

func ListenIP(network string, laddr *net.IPAddr) (rawHandle, error) {
	return nil, errors.New("os not supported")
}
