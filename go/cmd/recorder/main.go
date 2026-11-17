// Command recorder records every FIB change on one router.
//
// It joins the router's network namespace with setns, subscribes to the link,
// IPv4 route and nexthop netlink groups, dumps the starting state, then writes
// one JSON line per prefix whose effective next-hop set changed, stamped with
// CLOCK_MONOTONIC at receipt. Nexthop-object updates are resolved into the
// prefixes that use them (see internal/rtnl). A netlink buffer overrun
// (ENOBUFS) is counted, triggers a resync against a fresh dump, and marks the
// run invalid. SIGINT or SIGTERM stops it and writes a final stats line.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"sync/atomic"
	"syscall"

	"github.com/ritulrashi/convergence-microscope/go/internal/mono"
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

// apply feeds one message into the state and logs what changed.
func apply(st *rtnl.State, o *out, t int64, via string, m rtnl.Msg) error {
	switch m.Type {
	case rtnl.RTM_NEWROUTE, rtnl.RTM_DELROUTE:
		r, err := rtnl.ParseRoute(m.Data)
		if err != nil {
			return nil // non-IPv4 family on a shared group: ignore
		}
		o.changes(t, via, msgName[m.Type], st.ApplyRoute(r, m.Type == rtnl.RTM_DELROUTE))
	case rtnl.RTM_NEWNEXTHOP, rtnl.RTM_DELNEXTHOP:
		n, err := rtnl.ParseNexthop(m.Data)
		if err != nil {
			return err
		}
		o.changes(t, via, msgName[m.Type], st.ApplyNexthop(n, m.Type == rtnl.RTM_DELNEXTHOP))
	case rtnl.RTM_NEWLINK, rtnl.RTM_DELLINK:
		l, err := rtnl.ParseLink(m.Data)
		if err != nil {
			return err
		}
		st.ApplyLink(l, m.Type == rtnl.RTM_DELLINK)
		if via == "event" {
			o.rec(map[string]any{"kind": "link", "t": t, "ifname": st.Ifname(l.Index),
				"ifindex": l.Index, "up": l.Up, "lower_up": l.LowerUp, "msg": msgName[m.Type]})
		}
	}
	return nil
}

// dumpAll loads links, then nexthops, then routes into a fresh state.
func dumpAll(c *rtnl.Conn) (*rtnl.State, error) {
	st := rtnl.NewState()
	discard := &out{w: bufio.NewWriter(nopWriter{})}
	for _, typ := range []uint16{rtnl.RTM_GETLINK, rtnl.RTM_GETNEXTHOP, rtnl.RTM_GETROUTE} {
		ms, err := c.Dump(typ)
		if err != nil {
			return nil, fmt.Errorf("dump %d: %w", typ, err)
		}
		for _, m := range ms {
			if err := apply(st, discard, 0, "dump", m); err != nil {
				return nil, err
			}
		}
	}
	return st, nil
}

type nopWriter struct{}

func (nopWriter) Write(b []byte) (int, error) { return len(b), nil }

func main() {
	router := flag.String("router", "", "router name written on every record")
	netns := flag.String("netns", "", "network namespace path, e.g. /proc/<pid>/ns/net")
	outPath := flag.String("out", "-", "output JSONL (- = stdout)")
	rawPath := flag.String("raw", "", "also write every received datagram as hex (for test fixtures)")
	rcvbuf := flag.Int("rcvbuf", 32<<20, "monitor socket receive buffer bytes")
	ready := flag.String("ready", "", "file to create once subscribed and dumped")
	flag.Parse()
	if *router == "" || *netns == "" {
		fail(errors.New("need -router and -netns"))
	}

	// Everything below runs on this locked thread, inside the router's netns.
	if err := rtnl.EnterNetns(*netns); err != nil {
		fail(fmt.Errorf("setns %s: %w", *netns, err))
	}
	c, err := rtnl.Open(*rcvbuf)
	if err != nil {
		fail(err)
	}
	f := os.Stdout
	if *outPath != "-" {
		if f, err = os.Create(*outPath); err != nil {
			fail(err)
		}
	}
	o := &out{w: bufio.NewWriterSize(f, 1<<20), router: *router}
	var raw *bufio.Writer
	if *rawPath != "" {
		rf, err := os.Create(*rawPath)
		if err != nil {
			fail(err)
		}
		defer rf.Close()
		raw = bufio.NewWriter(rf)
	}

	// Subscribed first, so nothing between the dump and the first recv is lost.
	st, err := dumpAll(c)
	if err != nil {
		fail(err)
	}
	t0 := mono.Now()
	for _, p := range st.Prefixes() {
		o.rec(map[string]any{"kind": "init", "t": t0, "prefix": p.String(), "new": st.Effective(p)})
	}
	o.w.Flush()
	if *ready != "" {
		os.WriteFile(*ready, []byte("ok\n"), 0o644)
	}

	var stop atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; stop.Store(true) }()

	var datagrams, messages, overruns, parseErrs uint64
	for !stop.Load() {
		b, err := c.Recv()
		t := mono.Now()
		if errors.Is(err, rtnl.ErrOverrun) {
			overruns++
			o.rec(map[string]any{"kind": "overrun", "t": t})
			fresh, derr := dumpAll(c)
			if derr != nil {
				fail(derr)
			}
			o.changes(t, "resync", "DUMP", resync(st, fresh))
			st = fresh
			continue
		}
		if err != nil {
			fail(err)
		}
		if b == nil {
			continue
		}
		datagrams++
		if raw != nil {
			fmt.Fprintf(raw, "%d %s\n", t, hex.EncodeToString(b))
		}
		ms, err := rtnl.Split(b)
		if err != nil {
			parseErrs++
		}
		for _, m := range ms {
			messages++
			if err := apply(st, o, t, "event", m); err != nil {
				parseErrs++
			}
		}
		o.w.Flush()
	}
	valid := overruns == 0 && parseErrs == 0
	reason := ""
	if !valid {
		reason = fmt.Sprintf("%d netlink overruns, %d parse errors", overruns, parseErrs)
	}
	o.rec(map[string]any{"kind": "stats", "t": mono.Now(), "datagrams": datagrams, "messages": messages,
		"overruns": overruns, "parse_errors": parseErrs, "valid": valid, "invalid_reason": reason})
	o.w.Flush()
	if raw != nil {
		raw.Flush()
	}
}

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
