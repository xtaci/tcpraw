package tcpraw

import (
	"encoding/binary"
	"time"

	"github.com/google/gopacket/layers"
)

type FingerPrintType int

const (
	TypeLinux FingerPrintType = iota
)

type fingerPrint struct {
	Type    FingerPrintType
	Window  uint16
	Options []layers.TCPOption
	TTL     uint16
}

func (f fingerPrint) Clone() fingerPrint {
	c := f
	c.Options = make([]layers.TCPOption, len(f.Options))
	for i, opt := range f.Options {
		c.Options[i] = opt
		if opt.OptionData != nil {
			c.Options[i].OptionData = make([]byte, len(opt.OptionData))
			copy(c.Options[i].OptionData, opt.OptionData)
		}
	}
	return c
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

var seed uint32

func init() {
	seed = uint32(time.Now().UnixNano())
}

func makeOption(optType FingerPrintType, options []layers.TCPOption, tsecr uint32) {
	switch optType {
	case TypeLinux:
		// Timestamps: Kind 8, Length 10
		for i := range options {
			if options[i].OptionType == 8 && len(options[i].OptionData) == 10 {
				nowSeconds := time.Now().UnixNano() / 1e9
				binary.BigEndian.PutUint32(options[i].OptionData[:4], uint32(nowSeconds))
				binary.BigEndian.PutUint32(options[i].OptionData[4:], tsecr)
				break
			}
		}
	}
}
