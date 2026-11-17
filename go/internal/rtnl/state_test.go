package rtnl

import (
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
)

// --- message builders (the inverse of the parsers) ---

func nlattr(typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b := make([]byte, align(l))
	binary.LittleEndian.PutUint16(b[0:], uint16(l))
	binary.LittleEndian.PutUint16(b[2:], typ)
	copy(b[4:], data)
	return b
}

func u32(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }

func ip4(s string) []byte { a := netip.MustParseAddr(s).As4(); return a[:] }

func nlmsg(typ uint16, body []byte) []byte {
	l := 16 + len(body)
	b := make([]byte, align(l))
	binary.LittleEndian.PutUint32(b[0:], uint32(l))
	binary.LittleEndian.PutUint16(b[4:], typ)
	copy(b[16:], body)
	return b
}

func routeBody(prefix string, typ uint8, as ...[]byte) []byte {
	p := netip.MustParsePrefix(prefix)
	b := []byte{AF_INET, byte(p.Bits()), 0, 0, RT_TABLE_MAIN, 11, 0, typ, 0, 0, 0, 0}
	if p.Bits() > 0 {
		b = append(b, nlattr(RTA_DST, ip4(p.Addr().String()))...)
	}
	b = append(b, nlattr(RTA_TABLE, u32(RT_TABLE_MAIN))...)
	for _, a := range as {
		b = append(b, a...)
	}
	return b
}

func nhBody(id uint32, as ...[]byte) []byte {
	b := make([]byte, 8)
	b = append(b, nlattr(NHA_ID, u32(id))...)
	for _, a := range as {
		b = append(b, a...)
	}
	return b
}

func group(ids ...uint32) []byte {
	var g []byte
	for _, id := range ids {
		e := make([]byte, 8)
		binary.LittleEndian.PutUint32(e, id)
		g = append(g, e...)
	}
	return nlattr(NHA_GROUP, g)
}

func linkBody(idx uint32, name string, flags uint32) []byte {
	b := make([]byte, 16)
	binary.LittleEndian.PutUint32(b[4:], idx)
	binary.LittleEndian.PutUint32(b[8:], flags)
	return append(b, nlattr(IFLA_IFNAME, append([]byte(name), 0))...)
}

// feed applies a buffer of messages like the recorder does and returns the changes.
func feed(t *testing.T, s *State, buf []byte) []Change {
	t.Helper()
	ms, err := Split(buf)
	if err != nil {
		t.Fatal(err)
	}
	var out []Change
	for _, m := range ms {
		switch m.Type {
		case RTM_NEWROUTE, RTM_DELROUTE:
			r, err := ParseRoute(m.Data)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, s.ApplyRoute(r, m.Type == RTM_DELROUTE)...)
		case RTM_NEWNEXTHOP, RTM_DELNEXTHOP:
			n, err := ParseNexthop(m.Data)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, s.ApplyNexthop(n, m.Type == RTM_DELNEXTHOP)...)
		case RTM_NEWLINK:
			l, err := ParseLink(m.Data)
			if err != nil {
				t.Fatal(err)
			}
			s.ApplyLink(l, false)
		}
	}
	return out
}

func cat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

func ch(p string, old, nw []string) Change {
	return Change{netip.MustParsePrefix(p), old, nw}
}

func base(t *testing.T) *State {
	s := NewState()
	feed(t, s, cat(
		nlmsg(RTM_NEWLINK, linkBody(2, "eth1", IFF_UP|IFF_LOWER_UP)),
		nlmsg(RTM_NEWLINK, linkBody(3, "eth2", IFF_UP|IFF_LOWER_UP)),
		nlmsg(RTM_NEWNEXTHOP, nhBody(25, nlattr(NHA_GATEWAY, ip4("10.1.0.1")), nlattr(NHA_OIF, u32(2)))),
		nlmsg(RTM_NEWNEXTHOP, nhBody(28, nlattr(NHA_GATEWAY, ip4("10.1.0.3")), nlattr(NHA_OIF, u32(3)))),
		nlmsg(RTM_NEWNEXTHOP, nhBody(32, group(25, 28))),
	))
	return s
}

var both = []string{"10.1.0.1@eth1", "10.1.0.3@eth2"}

func TestRouteViaGroup(t *testing.T) {
	s := base(t)
	got := feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("10.0.0.4/32", RTN_UNICAST, nlattr(RTA_NH_ID, u32(32)))))
	want := []Change{ch("10.0.0.4/32", nil, both)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestGroupChangeIsRouteChange(t *testing.T) {
	// ECMP shrink arrives only as a nexthop-group update: it must still
	// be reported for every prefix using the group.
	s := base(t)
	feed(t, s, cat(
		nlmsg(RTM_NEWROUTE, routeBody("10.0.0.4/32", RTN_UNICAST, nlattr(RTA_NH_ID, u32(32)))),
		nlmsg(RTM_NEWROUTE, routeBody("10.10.4.0/24", RTN_UNICAST, nlattr(RTA_NH_ID, u32(32)))),
		nlmsg(RTM_NEWROUTE, routeBody("10.0.0.1/32", RTN_UNICAST, nlattr(RTA_NH_ID, u32(25)))),
	))
	got := feed(t, s, nlmsg(RTM_NEWNEXTHOP, nhBody(32, group(25))))
	want := []Change{
		ch("10.0.0.4/32", both, []string{"10.1.0.1@eth1"}),
		ch("10.10.4.0/24", both, []string{"10.1.0.1@eth1"}),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestMemberNexthopChange(t *testing.T) {
	s := base(t)
	feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("10.0.0.4/32", RTN_UNICAST, nlattr(RTA_NH_ID, u32(32)))))
	got := feed(t, s, nlmsg(RTM_NEWNEXTHOP, nhBody(28, nlattr(NHA_GATEWAY, ip4("10.1.0.9")), nlattr(NHA_OIF, u32(3)))))
	want := []Change{ch("10.0.0.4/32", both, []string{"10.1.0.1@eth1", "10.1.0.9@eth2"})}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestDeleteMemberThenGroup(t *testing.T) {
	s := base(t)
	feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("10.0.0.4/32", RTN_UNICAST, nlattr(RTA_NH_ID, u32(32)))))
	got := feed(t, s, nlmsg(RTM_DELNEXTHOP, nhBody(28)))
	if want := []Change{ch("10.0.0.4/32", both, []string{"10.1.0.1@eth1"})}; !reflect.DeepEqual(got, want) {
		t.Fatalf("member delete: got %v want %v", got, want)
	}
	got = feed(t, s, nlmsg(RTM_DELNEXTHOP, nhBody(25)))
	if want := []Change{ch("10.0.0.4/32", []string{"10.1.0.1@eth1"}, nil)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("last member delete: got %v want %v", got, want)
	}
	if len(s.Prefixes()) != 0 {
		t.Fatalf("route should be gone with its nexthop, have %v", s.Prefixes())
	}
}

func TestInlineMultipathBlackholeAndDelete(t *testing.T) {
	s := base(t)
	mp := func(oif uint32, gw string) []byte {
		a := nlattr(RTA_GATEWAY, ip4(gw))
		b := make([]byte, 8)
		binary.LittleEndian.PutUint16(b[0:], uint16(8+len(a)))
		binary.LittleEndian.PutUint32(b[4:], oif)
		return append(b, a...)
	}
	got := feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("192.0.2.0/24", RTN_UNICAST,
		nlattr(RTA_MULTIPATH, cat(mp(2, "10.1.0.1"), mp(3, "10.1.0.3"))))))
	if want := []Change{ch("192.0.2.0/24", nil, both)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("multipath: got %v", got)
	}
	got = feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("192.0.2.0/24", RTN_BLACKHOLE)))
	if want := []Change{ch("192.0.2.0/24", both, []string{"blackhole"})}; !reflect.DeepEqual(got, want) {
		t.Fatalf("blackhole: got %v", got)
	}
	got = feed(t, s, nlmsg(RTM_DELROUTE, routeBody("192.0.2.0/24", RTN_BLACKHOLE)))
	if want := []Change{ch("192.0.2.0/24", []string{"blackhole"}, nil)}; !reflect.DeepEqual(got, want) {
		t.Fatalf("delete: got %v", got)
	}
}

func TestConnectedAndIgnoredTables(t *testing.T) {
	s := base(t)
	got := feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("10.10.1.0/24", RTN_UNICAST, nlattr(RTA_OIF, u32(2)))))
	if want := []Change{ch("10.10.1.0/24", nil, []string{"direct@eth1"})}; !reflect.DeepEqual(got, want) {
		t.Fatalf("connected: got %v", got)
	}
	// Local-table route: ignored.
	b := routeBody("10.10.1.1/32", RTN_LOCAL, nlattr(RTA_OIF, u32(2)))
	b[4] = 255
	copy(b[len(b)-4:], u32(255)) // RTA_TABLE is the last attr
	if got := feed(t, s, nlmsg(RTM_NEWROUTE, b)); len(got) != 0 {
		t.Fatalf("local table not ignored: %v", got)
	}
}

func TestRouteBeforeItsNexthop(t *testing.T) {
	s := NewState()
	got := feed(t, s, nlmsg(RTM_NEWROUTE, routeBody("10.0.0.9/32", RTN_UNICAST, nlattr(RTA_NH_ID, u32(77)))))
	if want := []Change{ch("10.0.0.9/32", nil, []string{"unresolved-nh:77"})}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	got = feed(t, s, nlmsg(RTM_NEWNEXTHOP, nhBody(77, nlattr(NHA_BLACKHOLE, nil))))
	if want := []Change{ch("10.0.0.9/32", []string{"unresolved-nh:77"}, []string{"blackhole"})}; !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestSplitRejectsTruncated(t *testing.T) {
	b := nlmsg(RTM_NEWROUTE, routeBody("10.0.0.4/32", RTN_UNICAST))
	if _, err := Split(b[:len(b)-8]); err == nil {
		t.Fatal("truncated buffer accepted")
	}
}
