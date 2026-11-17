// Package rtnl parses the rtnetlink messages the recorder needs (IPv4 routes,
// nexthop objects, links) and keeps the per-prefix effective next-hop sets.
//
// Parsing is pure Go over byte slices so it is tested with recorded netlink
// fixtures on any OS; only socket.go is Linux-specific.
package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
)

// Message types (linux/rtnetlink.h).
const (
	NLMSG_NOOP     = 1
	NLMSG_ERROR    = 2
	NLMSG_DONE     = 3
	RTM_NEWLINK    = 16
	RTM_DELLINK    = 17
	RTM_NEWROUTE   = 24
	RTM_DELROUTE   = 25
	RTM_GETROUTE   = 26
	RTM_NEWNEXTHOP = 104
	RTM_DELNEXTHOP = 105
	RTM_GETNEXTHOP = 106
	RTM_GETLINK    = 18
)

// Route attributes.
const (
	RTA_DST       = 1
	RTA_OIF       = 4
	RTA_GATEWAY   = 5
	RTA_PRIORITY  = 6
	RTA_MULTIPATH = 9
	RTA_TABLE     = 15
	RTA_NH_ID     = 30
)

// Route types.
const (
	RTN_UNICAST     = 1
	RTN_LOCAL       = 2
	RTN_BROADCAST   = 3
	RTN_BLACKHOLE   = 6
	RTN_UNREACHABLE = 7
	RTN_PROHIBIT    = 8
)

// Nexthop attributes.
const (
	NHA_ID        = 1
	NHA_GROUP     = 2
	NHA_BLACKHOLE = 4
	NHA_OIF       = 5
	NHA_GATEWAY   = 6
)

const (
	IFLA_IFNAME   = 3
	IFF_UP        = 0x1
	IFF_LOWER_UP  = 0x10000
	RT_TABLE_MAIN = 254
	AF_INET       = 2
)

var errTrunc = errors.New("rtnl: truncated message")

// Msg is one netlink message: header type plus its payload.
type Msg struct {
	Type uint16
	Data []byte
}

// Split splits a buffer returned by one recv into netlink messages.
func Split(b []byte) ([]Msg, error) {
	var out []Msg
	for len(b) >= 16 {
		l := int(binary.LittleEndian.Uint32(b[0:4]))
		if l < 16 || l > len(b) {
			return out, errTrunc
		}
		out = append(out, Msg{Type: binary.LittleEndian.Uint16(b[4:6]), Data: b[16:l]})
		b = b[align(l):]
	}
	return out, nil
}

func align(n int) int { return (n + 3) &^ 3 }

type attr struct {
	typ  uint16
	data []byte
}

func attrs(b []byte) ([]attr, error) {
	var out []attr
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		if l < 4 || l > len(b) {
			return out, errTrunc
		}
		out = append(out, attr{binary.LittleEndian.Uint16(b[2:4]) & 0x3fff, b[4:l]})
		if align(l) > len(b) {
			break
		}
		b = b[align(l):]
	}
	return out, nil
}

// Hop is one resolved next hop. Gateway is invalid for directly connected
// routes. Kind is "" for normal hops, or "blackhole"/"unreachable"/"prohibit".
type Hop struct {
	Gateway netip.Addr
	Oif     uint32
	Kind    string
}

// Route is a parsed IPv4 route message (main table only is kept by State).
type Route struct {
	Prefix netip.Prefix
	Table  uint32
	Type   uint8
	NhID   uint32
	Inline []Hop
}

// ParseRoute parses an RTM_NEWROUTE/RTM_DELROUTE payload.
func ParseRoute(b []byte) (Route, error) {
	if len(b) < 12 {
		return Route{}, errTrunc
	}
	family, dstLen, table, typ := b[0], int(b[1]), uint32(b[4]), b[7]
	if family != AF_INET {
		return Route{}, fmt.Errorf("rtnl: family %d", family)
	}
	r := Route{Table: table, Type: typ}
	dst := netip.AddrFrom4([4]byte{})
	var gw netip.Addr
	var oif uint32
	as, err := attrs(b[12:])
	if err != nil {
		return r, err
	}
	for _, a := range as {
		switch a.typ {
		case RTA_DST:
			if len(a.data) == 4 {
				dst = netip.AddrFrom4([4]byte(a.data))
			}
		case RTA_TABLE:
			if len(a.data) >= 4 {
				r.Table = binary.LittleEndian.Uint32(a.data)
			}
		case RTA_GATEWAY:
			if len(a.data) == 4 {
				gw = netip.AddrFrom4([4]byte(a.data))
			}
		case RTA_OIF:
			if len(a.data) >= 4 {
				oif = binary.LittleEndian.Uint32(a.data)
			}
		case RTA_NH_ID:
			if len(a.data) >= 4 {
				r.NhID = binary.LittleEndian.Uint32(a.data)
			}
		case RTA_MULTIPATH:
			hops, err := parseMultipath(a.data)
			if err != nil {
				return r, err
			}
			r.Inline = append(r.Inline, hops...)
		}
	}
	r.Prefix = netip.PrefixFrom(dst, dstLen)
	switch typ {
	case RTN_BLACKHOLE:
		r.Inline = []Hop{{Kind: "blackhole"}}
	case RTN_UNREACHABLE:
		r.Inline = []Hop{{Kind: "unreachable"}}
	case RTN_PROHIBIT:
		r.Inline = []Hop{{Kind: "prohibit"}}
	default:
		if len(r.Inline) == 0 && (gw.IsValid() || oif != 0) {
			r.Inline = []Hop{{Gateway: gw, Oif: oif}}
		}
	}
	return r, nil
}

func parseMultipath(b []byte) ([]Hop, error) {
	var out []Hop
	for len(b) >= 8 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		if l < 8 || l > len(b) {
			return out, errTrunc
		}
		h := Hop{Oif: binary.LittleEndian.Uint32(b[4:8])}
		as, err := attrs(b[8:l])
		if err != nil {
			return out, err
		}
		for _, a := range as {
			if a.typ == RTA_GATEWAY && len(a.data) == 4 {
				h.Gateway = netip.AddrFrom4([4]byte(a.data))
			}
		}
		out = append(out, h)
		b = b[align(l):]
	}
	return out, nil
}

// Nexthop is a parsed nexthop object: either a single hop or a group.
type Nexthop struct {
	ID    uint32
	Hop   Hop
	Group []uint32
}

// ParseNexthop parses an RTM_NEWNEXTHOP/RTM_DELNEXTHOP payload.
func ParseNexthop(b []byte) (Nexthop, error) {
	if len(b) < 8 {
		return Nexthop{}, errTrunc
	}
	var n Nexthop
	as, err := attrs(b[8:])
	if err != nil {
		return n, err
	}
	for _, a := range as {
		switch a.typ {
		case NHA_ID:
			if len(a.data) >= 4 {
				n.ID = binary.LittleEndian.Uint32(a.data)
			}
		case NHA_GROUP:
			for g := a.data; len(g) >= 8; g = g[8:] {
				n.Group = append(n.Group, binary.LittleEndian.Uint32(g[0:4]))
			}
		case NHA_BLACKHOLE:
			n.Hop.Kind = "blackhole"
		case NHA_OIF:
			if len(a.data) >= 4 {
				n.Hop.Oif = binary.LittleEndian.Uint32(a.data)
			}
		case NHA_GATEWAY:
			if len(a.data) == 4 {
				n.Hop.Gateway = netip.AddrFrom4([4]byte(a.data))
			}
		}
	}
	if n.ID == 0 {
		return n, errors.New("rtnl: nexthop without id")
	}
	return n, nil
}

// Link is a parsed link message.
type Link struct {
	Index   uint32
	Name    string
	Up      bool
	LowerUp bool
}

// ParseLink parses an RTM_NEWLINK/RTM_DELLINK payload.
func ParseLink(b []byte) (Link, error) {
	if len(b) < 16 {
		return Link{}, errTrunc
	}
	flags := binary.LittleEndian.Uint32(b[8:12])
	l := Link{
		Index:   binary.LittleEndian.Uint32(b[4:8]),
		Up:      flags&IFF_UP != 0,
		LowerUp: flags&IFF_LOWER_UP != 0,
	}
	as, err := attrs(b[16:])
	if err != nil {
		return l, err
	}
	for _, a := range as {
		if a.typ == IFLA_IFNAME {
			n := a.data
			for len(n) > 0 && n[len(n)-1] == 0 {
				n = n[:len(n)-1]
			}
			l.Name = string(n)
		}
	}
	return l, nil
}
