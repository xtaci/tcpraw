// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// +build linux

package afpacket

import (
	"reflect"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

///////////////////////////////////////////////////////////////////////////////
// below are the structs and defines in <linux/af_packet.h>
// required by AF_PACKET
const VLAN_HLEN = 4
const ETH_ALEN = 6

/*
struct tpacket_req {
    unsigned int    tp_block_size;
    unsigned int    tp_block_nr;
    unsigned int    tp_frame_size;
    unsigned int    tp_frame_nr;
};
*/

type tpacket_req struct {
	tp_block_size uint32
	tp_block_nr   uint32
	tp_frame_size uint32
	tp_frame_nr   uint32
}

/*
<linux/if_packet.h>

struct tpacket_hdr {
	unsigned long	tp_status;
	unsigned int	tp_len;
	unsigned int	tp_snaplen;
	unsigned short	tp_mac;
	unsigned short	tp_net;
	unsigned int	tp_sec;
	unsigned int	tp_usec;
};

struct tpacket2_hdr {
    __u32           tp_status;
    __u32           tp_len;
    __u32           tp_snaplen;
    __u16           tp_mac;
    __u16           tp_net;
    __u32           tp_sec;
    __u32           tp_nsec;
    __u16           tp_vlan_tci;
    __u16           tp_vlan_tpid;
    __u8            tp_padding[4];
};
*/

type v1header struct {
	tp_status  uint
	tp_len     uint32
	tp_snaplen uint32
	tp_mac     uint16
	tp_net     uint16
	tp_sec     uint32
	tp_usec    uint32
}

type v2header struct {
	tp_status    uint32
	tp_len       uint32
	tp_snaplen   uint32
	tp_mac       uint16
	tp_net       uint16
	tp_sec       uint32
	tp_nsec      uint32
	tp_vlan_tci  uint16
	tp_vlan_tpid uint16
	tp_padding   [4]uint8
}

/*
struct tpacket_stats {
	unsigned int	tp_packets;
	unsigned int	tp_drops;
};
*/

// SocketStats is a struct where socket stats are stored
type SocketStats struct {
	tp_packets uint32
	tp_drops   uint32
}

// Packets returns the number of packets seen by this socket.
func (s *SocketStats) Packets() uint {
	return uint(s.tp_packets)
}

// Drops returns the number of packets dropped on this socket.
func (s *SocketStats) Drops() uint {
	return uint(s.tp_drops)
}

/*
struct sockaddr_ll {
	unsigned short	sll_family;
	__be16		sll_protocol;
	int		sll_ifindex;
	unsigned short	sll_hatype;
	unsigned char	sll_pkttype;
	unsigned char	sll_halen;
	unsigned char	sll_addr[8];
};
*/

type sockaddr_ll struct {
	sll_family   uint16
	sll_protocol uint16
	sll_ifindex  int32
	sll_hatype   uint16
	sll_pkttype  byte
	sll_halen    byte
	sll_addr     [8]byte
}

/*
#define TPACKET_ALIGNMENT	16
#define TPACKET_ALIGN(x)	(((x)+TPACKET_ALIGNMENT-1)&~(TPACKET_ALIGNMENT-1))
*/
const tpacketAlignment = uint(unix.TPACKET_ALIGNMENT)

func tpAlign(x int) int {
	return int((uint(x) + tpacketAlignment - 1) &^ (tpacketAlignment - 1))
}

////////////////////////////////////////////////////////////////////////////////
// Our model of handling all TPacket versions is a little hacky, to say the
// least.  We use the header interface to handle interactions with the
// tpacket1/tpacket2 packet header.

type header interface {
	// getStatus returns the TPacket status of the current header.
	getStatus() int
	// clearStatus clears the status of the current header, releasing its
	// underlying data back to the kernel for future use with new packets.
	// Using the header after calling clearStatus is an error.  clearStatus
	// should only be called after next() returns false.
	clearStatus()
	// getTime returns the timestamp for the current packet pointed to by
	// the header.
	getTime() time.Time
	// getData returns the packet data pointed to by the current header.
	getData(opts *options) []byte
	// getLength returns the total length of the packet.
	getLength() int
	// getIfaceIndex returns the index of the network interface
	// where the packet was seen. The index can later be translated to a name.
	getIfaceIndex() int
	// getVLAN returns the VLAN of a packet if it was provided out-of-band
	getVLAN() int
	// next moves this header to point to the next packet it contains,
	// returning true on success (in which case getTime and getData will
	// return values for the new packet) or false if there are no more
	// packets (in which case clearStatus should be called).
	next() bool
}

func makeSlice(start uintptr, length int) (data []byte) {
	slice := (*reflect.SliceHeader)(unsafe.Pointer(&data))
	slice.Data = start
	slice.Len = length
	slice.Cap = length
	return
}

func insertVlanHeader(data []byte, vlanTCI int, opts *options) []byte {
	if vlanTCI == 0 || !opts.addVLANHeader {
		return data
	}
	eth := make([]byte, 0, len(data)+VLAN_HLEN)
	eth = append(eth, data[0:ETH_ALEN*2]...)
	eth = append(eth, []byte{0x81, 0, byte((vlanTCI >> 8) & 0xff), byte(vlanTCI & 0xff)}...)
	return append(eth, data[ETH_ALEN*2:]...)
}

func (h *v1header) getVLAN() int {
	return -1
}
func (h *v1header) getStatus() int {
	return int(h.tp_status)
}
func (h *v1header) clearStatus() {
	h.tp_status = 0
}
func (h *v1header) getTime() time.Time {
	return time.Unix(int64(h.tp_sec), int64(h.tp_usec)*1000)
}
func (h *v1header) getData(opts *options) []byte {
	return makeSlice(uintptr(unsafe.Pointer(h))+uintptr(h.tp_mac), int(h.tp_snaplen))
}
func (h *v1header) getLength() int {
	return int(h.tp_len)
}
func (h *v1header) getIfaceIndex() int {
	ll := (*sockaddr_ll)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(int(unsafe.Sizeof(v1header{}))))))
	return int(ll.sll_ifindex)
}
func (h *v1header) next() bool {
	return false
}

func (h *v2header) getVLAN() int {
	return -1
}
func (h *v2header) getStatus() int {
	return int(h.tp_status)
}
func (h *v2header) clearStatus() {
	h.tp_status = 0
}
func (h *v2header) getTime() time.Time {
	return time.Unix(int64(h.tp_sec), int64(h.tp_nsec))
}
func (h *v2header) getData(opts *options) []byte {
	data := makeSlice(uintptr(unsafe.Pointer(h))+uintptr(h.tp_mac), int(h.tp_snaplen))
	return insertVlanHeader(data, int(h.tp_vlan_tci), opts)
}
func (h *v2header) getLength() int {
	return int(h.tp_len)
}
func (h *v2header) getIfaceIndex() int {
	ll := (*sockaddr_ll)(unsafe.Pointer(uintptr(unsafe.Pointer(h)) + uintptr(tpAlign(int(unsafe.Sizeof(v2header{}))))))
	return int(ll.sll_ifindex)
}
func (h *v2header) next() bool {
	return false
}
