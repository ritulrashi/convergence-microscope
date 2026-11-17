// Recorder logic shared by main (Linux) and the replay tests (any OS).

package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"

	"github.com/ritulrashi/convergence-microscope/go/internal/rtnl"
)

type out struct {
	w      *bufio.Writer
	router string
}

func (o *out) rec(v map[string]any) {
	v["router"] = o.router
	b, _ := json.Marshal(v)
	o.w.Write(b)
	o.w.WriteByte('\n')
}

func (o *out) changes(t int64, via, msg string, cs []rtnl.Change) {
	for _, c := range cs {
		o.rec(map[string]any{"kind": "fib", "t": t, "prefix": c.Prefix.String(),
			"old": nonNil(c.Old), "new": nonNil(c.New), "via": via, "msg": msg})
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

var msgName = map[uint16]string{
	rtnl.RTM_NEWROUTE: "NEWROUTE", rtnl.RTM_DELROUTE: "DELROUTE",
	rtnl.RTM_NEWNEXTHOP: "NEWNEXTHOP", rtnl.RTM_DELNEXTHOP: "DELNEXTHOP",
	rtnl.RTM_NEWLINK: "NEWLINK", rtnl.RTM_DELLINK: "DELLINK",
}

// apply feeds one message into the state and logs what changed. It reports
// whether the message took a link down (the caller then cross-checks).
func apply(st *rtnl.State, o *out, t int64, via string, m rtnl.Msg) (bool, error) {
	switch m.Type {
	case rtnl.RTM_NEWROUTE, rtnl.RTM_DELROUTE:
		r, err := rtnl.ParseRoute(m.Data)
		if err != nil {
			return false, nil // non-IPv4 family on a shared group: ignore
		}
		o.changes(t, via, msgName[m.Type], st.ApplyRoute(r, m.Type == rtnl.RTM_DELROUTE))
	case rtnl.RTM_NEWNEXTHOP, rtnl.RTM_DELNEXTHOP:
		n, err := rtnl.ParseNexthop(m.Data)
		if err != nil {
			return false, err
		}
		o.changes(t, via, msgName[m.Type], st.ApplyNexthop(n, m.Type == rtnl.RTM_DELNEXTHOP))
	case rtnl.RTM_NEWLINK, rtnl.RTM_DELLINK:
		l, err := rtnl.ParseLink(m.Data)
		if err != nil {
			return false, err
		}
		if via == "event" {
			o.rec(map[string]any{"kind": "link", "t": t, "ifname": st.Ifname(l.Index),
				"ifindex": l.Index, "up": l.Up, "running": l.Running, "lower_up": l.LowerUp,
				"msg": msgName[m.Type]})
		}
		// The kernel flushes FIB state on link down without netlink messages.
		o.changes(t, "link-flush", msgName[m.Type], st.ApplyLink(l, m.Type == rtnl.RTM_DELLINK))
		return l.AdminDown() || l.CarrierDown(), nil
	}
	return false, nil
}

// rawLog writes "<t> <dump|event> <hex>" lines: the recorder's whole input,
// replayable by the tests.
type rawLog struct{ w *bufio.Writer }

func (r *rawLog) put(t int64, kind string, b []byte) {
	if r == nil {
		return
	}
	fmt.Fprintf(r.w, "%d %s %s\n", t, kind, hex.EncodeToString(b))
}

type nopWriter struct{}

func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }

// resync reports every prefix whose set differs between the old and new state.
func resync(old, fresh *rtnl.State) []rtnl.Change {
	seen := map[netip.Prefix]bool{}
	var cs []rtnl.Change
	for _, s := range []*rtnl.State{old, fresh} {
		for _, p := range s.Prefixes() {
			if seen[p] {
				continue
			}
			seen[p] = true
			a, b := old.Effective(p), fresh.Effective(p)
			if !slices.Equal(a, b) {
				cs = append(cs, rtnl.Change{Prefix: p, Old: a, New: b})
			}
		}
	}
	return cs
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "recorder:", err)
	os.Exit(2)
}
