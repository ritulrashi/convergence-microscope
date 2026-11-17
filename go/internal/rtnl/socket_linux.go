package rtnl

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"

	"golang.org/x/sys/unix"
)

// Multicast groups (enum rtnetlink_groups).
const (
	RTNLGRP_LINK       = 1
	RTNLGRP_IPV4_ROUTE = 7
	RTNLGRP_NEXTHOP    = 32
)

// ErrOverrun is returned by Recv when the kernel dropped messages because the
// socket buffer was full (ENOBUFS). The caller must resynchronise.
var ErrOverrun = errors.New("rtnl: netlink receive buffer overrun (ENOBUFS)")

// Conn is a monitor socket plus a request socket, both created inside one
// network namespace.
type Conn struct {
	mon, req int
	seq      uint32
	buf      []byte
}

// EnterNetns locks the calling goroutine to its OS thread and moves that
// thread into the network namespace at path. Sockets created afterwards on
// this thread belong to that namespace for their whole life.
func EnterNetns(path string) error {
	runtime.LockOSThread()
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return unix.Setns(int(f.Fd()), unix.CLONE_NEWNET)
}

// Open creates the sockets in the current thread's namespace. rcvbuf is the
// monitor socket's receive buffer in bytes (set with SO_RCVBUFFORCE).
func Open(rcvbuf int) (*Conn, error) {
	mon, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(mon, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	for _, g := range []int{RTNLGRP_LINK, RTNLGRP_IPV4_ROUTE, RTNLGRP_NEXTHOP} {
		if err := unix.SetsockoptInt(mon, unix.SOL_NETLINK, unix.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			return nil, fmt.Errorf("join group %d: %w", g, err)
		}
	}
	if err := unix.SetsockoptInt(mon, unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, rcvbuf); err != nil {
		if err := unix.SetsockoptInt(mon, unix.SOL_SOCKET, unix.SO_RCVBUF, rcvbuf); err != nil {
			return nil, err
		}
	}
	tv := unix.Timeval{Usec: 200000}
	if err := unix.SetsockoptTimeval(mon, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}
	req, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	if err := unix.Bind(req, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	return &Conn{mon: mon, req: req, buf: make([]byte, 1<<20)}, nil
}

// Recv blocks for up to 200 ms and returns the raw bytes of one datagram
// (possibly several messages). It returns (nil, nil) on timeout.
func (c *Conn) Recv() ([]byte, error) {
	n, _, err := unix.Recvfrom(c.mon, c.buf, 0)
	if err != nil {
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			return nil, nil
		}
		if errors.Is(err, unix.ENOBUFS) {
			return nil, ErrOverrun
		}
		return nil, err
	}
	return c.buf[:n], nil
}

// Dump sends a dump request of type typ and returns every reply message.
func (c *Conn) Dump(typ uint16) ([]Msg, error) {
	c.seq++
	var body []byte
	switch typ {
	case RTM_GETROUTE:
		body = make([]byte, 12) // rtmsg
		body[0] = AF_INET
	case RTM_GETNEXTHOP:
		body = make([]byte, 8) // nhmsg, family unspec: all nexthops
	case RTM_GETLINK:
		body = make([]byte, 16) // ifinfomsg
	default:
		return nil, fmt.Errorf("rtnl: no dump for type %d", typ)
	}
	msg := make([]byte, 16+len(body))
	binary.LittleEndian.PutUint32(msg[0:], uint32(len(msg)))
	binary.LittleEndian.PutUint16(msg[4:], typ)
	binary.LittleEndian.PutUint16(msg[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.LittleEndian.PutUint32(msg[8:], c.seq)
	copy(msg[16:], body)
	if err := unix.Sendto(c.req, msg, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var out []Msg
	buf := make([]byte, 1<<20)
	for {
		n, _, err := unix.Recvfrom(c.req, buf, 0)
		if err != nil {
			return nil, err
		}
		ms, err := Split(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			switch m.Type {
			case NLMSG_DONE:
				return out, nil
			case NLMSG_ERROR:
				if len(m.Data) >= 4 && int32(binary.LittleEndian.Uint32(m.Data)) != 0 {
					return nil, fmt.Errorf("rtnl: dump %d: errno %d", typ, -int32(binary.LittleEndian.Uint32(m.Data)))
				}
				return out, nil
			default:
				out = append(out, Msg{Type: m.Type, Data: append([]byte(nil), m.Data...)})
			}
		}
	}
}

func (c *Conn) Close() {
	unix.Close(c.mon)
	unix.Close(c.req)
}
