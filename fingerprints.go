package tcpraw

import "github.com/google/gopacket/layers"

type fingerPrint struct {
	Window  uint16
	Options []layers.TCPOption
}

var fingerPrintWindows = fingerPrint{
	Window: 64240,
	Options: []layers.TCPOption{
		{2, 4, []byte{0, 0, 0xb4, 5}}, // 1460 = 0x5b4 MSS
		{1, 0, nil},
		{3, 3, []byte{0, 0, 8}}, // Window scale:8
		{1, 0, nil},
		{1, 0, nil},
		{4, 0, nil},
	},
}
