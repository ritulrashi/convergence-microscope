//go:build linux

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
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ritulrashi/convergence-microscope/go/internal/mono"
	"github.com/ritulrashi/convergence-microscope/go/internal/rtnl"
)

// dumpAll loads links, then nexthops, then routes into a fresh state.
func dumpAll(c *rtnl.Conn, raw *rawLog) (*rtnl.State, error) {
	st := rtnl.NewState()
	discard := &out{w: bufio.NewWriter(nopWriter{})}
	for _, typ := range []uint16{rtnl.RTM_GETLINK, rtnl.RTM_GETNEXTHOP, rtnl.RTM_GETROUTE} {
		ms, err := c.Dump(typ)
		if err != nil {
			return nil, fmt.Errorf("dump %d: %w", typ, err)
		}
		t := mono.Now()
		for _, m := range ms {
			raw.put(t, "dump", m.Encode())
			if _, err := apply(st, discard, 0, "dump", m); err != nil {
				return nil, err
			}
		}
	}
	return st, nil
}

func main() {
	router := flag.String("router", "", "router name written on every record")
	netns := flag.String("netns", "", "network namespace path, e.g. /proc/<pid>/ns/net")
	outPath := flag.String("out", "-", "output JSONL (- = stdout)")
	rawPath := flag.String("raw", "", "also write every received datagram as hex (for test fixtures)")
	rcvbuf := flag.Int("rcvbuf", 32<<20, "monitor socket receive buffer bytes")
	ready := flag.String("ready", "", "file to create once subscribed and dumped")
	check := flag.Duration("check-after-link-down", 100*time.Millisecond,
		"cross-check the modelled link-down flush against a fresh dump this long after it (0 = off)")
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
	var raw *rawLog
	if *rawPath != "" {
		rf, err := os.Create(*rawPath)
		if err != nil {
			fail(err)
		}
		defer rf.Close()
		raw = &rawLog{bufio.NewWriter(rf)}
	}

	// Subscribed first, so nothing between the dump and the first recv is lost.
	st, err := dumpAll(c, raw)
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

	var datagrams, messages, overruns, parseErrs, checks, mismatches uint64
	var checkAt int64 // when to cross-check the model against a fresh dump
	for !stop.Load() {
		b, err := c.Recv()
		t := mono.Now()
		if checkAt != 0 && t >= checkAt {
			checkAt = 0
			fresh, derr := dumpAll(c, nil)
			if derr != nil {
				fail(derr)
			}
			diff := resync(st, fresh)
			checks++
			mismatches += uint64(len(diff))
			rows := []map[string]any{}
			for _, d := range diff {
				rows = append(rows, map[string]any{"prefix": d.Prefix.String(),
					"recorded": nonNil(d.Old), "kernel": nonNil(d.New)})
			}
			o.rec(map[string]any{"kind": "check", "t": t, "t_done": mono.Now(), "mismatches": rows})
			o.w.Flush()
		}
		if errors.Is(err, rtnl.ErrOverrun) {
			overruns++
			o.rec(map[string]any{"kind": "overrun", "t": t})
			fresh, derr := dumpAll(c, raw)
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
		raw.put(t, "event", b)
		ms, err := rtnl.Split(b)
		if err != nil {
			parseErrs++
		}
		for _, m := range ms {
			messages++
			down, err := apply(st, o, t, "event", m)
			if err != nil {
				parseErrs++
			}
			if down && *check > 0 {
				checkAt = t + check.Nanoseconds()
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
		"overruns": overruns, "parse_errors": parseErrs, "link_down_checks": checks,
		"check_mismatches": mismatches, "valid": valid, "invalid_reason": reason})
	o.w.Flush()
	if raw != nil {
		raw.w.Flush()
	}
}
