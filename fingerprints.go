package tcpraw

import (
	"encoding/binary"
	"time"

	"github.com/google/gopacket/layers"
)

type FingerPrintType int

var seed uint64

func init() {
	seed = uint64(time.Now().UnixNano())
}

const (
	TypeLinux FingerPrintType = iota
)

type fingerPrint struct {
	Type    FingerPrintType
	Window  uint16
	Options []layers.TCPOption
	TTL     uint16
}

// options [nop,nop,TS val 1940162183 ecr 1366690553]
var fingerPrintLinux = fingerPrint{
	Type:   TypeLinux,
	Window: 65535,
	Options: []layers.TCPOption{
		{1, 0, nil},
		{1, 0, nil},
		{8, 10, make([]byte, 10)}, // len = 10
	},
	TTL: 64,
}

var defaultFingerPrint = fingerPrintLinux

func makeOption(optType FingerPrintType, options []layers.TCPOption) {
	switch optType {
	case TypeLinux:
		nowMilli := (seed + uint64(time.Now().UnixNano())/1e9) & 0xFFFFFFFF
		binary.BigEndian.PutUint32(options[2].OptionData[6:], uint32(nowMilli))
	}
}
