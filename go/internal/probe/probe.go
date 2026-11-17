// Package probe defines the UDP probe payload.
//
// Layout (little endian, 28 bytes, padded to Size):
//
//	0  magic   u32  0x52504d43 ("CMPR")
//	4  version u8
//	5  src     u8   source host id
//	6  dst     u8   destination host id
//	7  _       u8
//	8  sport   u16  UDP source port the sender used
//	10 _       u16
//	12 seq     u64  per (src, dst) pair
//	20 sent    i64  CLOCK_MONOTONIC ns at send
//
// The eBPF tracer matches on UDP destination port plus the magic at payload
// offset 0, so both are fixed here and mirrored in bpf/tracer.bpf.c.
package probe

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	Magic   uint32 = 0x52504d43
	Version uint8  = 1
	Port    uint16 = 7777
	Size           = 32
)

var ErrShort = errors.New("probe: payload too short")

// Probe is one decoded probe payload.
type Probe struct {
	Src, Dst uint8
	Sport    uint16
	Seq      uint64
	SentNs   int64
}

// FlowID names a flow: source host, destination host, source port.
type FlowID struct {
	Src, Dst uint8
	Sport    uint16
}

func (p Probe) Flow() FlowID { return FlowID{p.Src, p.Dst, p.Sport} }

func (f FlowID) String() string { return fmt.Sprintf("%d>%d:%d", f.Src, f.Dst, f.Sport) }

// Encode writes p into b, which must be at least Size bytes, and returns b[:Size].
func (p Probe) Encode(b []byte) []byte {
	b = b[:Size]
	clear(b)
	binary.LittleEndian.PutUint32(b[0:], Magic)
	b[4] = Version
	b[5] = p.Src
	b[6] = p.Dst
	binary.LittleEndian.PutUint16(b[8:], p.Sport)
	binary.LittleEndian.PutUint64(b[12:], p.Seq)
	binary.LittleEndian.PutUint64(b[20:], uint64(p.SentNs))
	return b
}

// Decode parses a payload. It rejects short buffers, a wrong magic and an
// unknown version.
func Decode(b []byte) (Probe, error) {
	if len(b) < 28 {
		return Probe{}, ErrShort
	}
	if m := binary.LittleEndian.Uint32(b[0:]); m != Magic {
		return Probe{}, fmt.Errorf("probe: bad magic %#x", m)
	}
	if b[4] != Version {
		return Probe{}, fmt.Errorf("probe: unknown version %d", b[4])
	}
	return Probe{
		Src:    b[5],
		Dst:    b[6],
		Sport:  binary.LittleEndian.Uint16(b[8:]),
		Seq:    binary.LittleEndian.Uint64(b[12:]),
		SentNs: int64(binary.LittleEndian.Uint64(b[20:])),
	}, nil
}

// Schedule is the deterministic send plan for one (src, dst) pair: packet seq
// is due at Start + seq*Interval and leaves from Ports[seq % len(Ports)].
type Schedule struct {
	StartNs    int64
	IntervalNs int64
	Ports      []uint16
}

func (s Schedule) Due(seq uint64) int64   { return s.StartNs + int64(seq)*s.IntervalNs }
func (s Schedule) Port(seq uint64) uint16 { return s.Ports[seq%uint64(len(s.Ports))] }
