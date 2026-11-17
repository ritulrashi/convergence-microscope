//go:build linux

// Command tracer loads bpf/tracer.bpf.c and writes one JSON line per probe
// packet event: every hop's ingress (rx) and every drop with its kernel drop
// reason. Namespace inodes are mapped to router names with a table built at
// startup from -ns name=/proc/<pid>/ns/net arguments.
//
// Ring-buffer reservations that fail are counted; any loss marks the run
// invalid. SIGINT or SIGTERM stops it and writes a final stats line.
package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/ritulrashi/convergence-microscope/go/internal/mono"
	"github.com/ritulrashi/convergence-microscope/go/internal/probe"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target bpfel tracer ../../../bpf/tracer.bpf.c -- -I../../../bpf

type nsFlags map[uint32]string

func (n nsFlags) String() string { return fmt.Sprint(map[uint32]string(n)) }

func (n nsFlags) Set(v string) error {
	name, path, ok := strings.Cut(v, "=")
	if !ok {
		return fmt.Errorf("want name=path, got %q", v)
	}
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	n[uint32(st.Ino)] = name
	return nil
}

// event mirrors struct event in tracer.bpf.c (48 bytes).
type event struct {
	TsNs, Location, Seq          uint64
	Netns, Ifindex, Reason       uint32
	Sport                        uint16
	Kind, TTL, Src, Dst, FromMap uint8
}

func decode(b []byte) (event, error) {
	if len(b) < 43 {
		return event{}, errors.New("short event")
	}
	le := binary.LittleEndian
	return event{
		TsNs: le.Uint64(b[0:]), Location: le.Uint64(b[8:]), Seq: le.Uint64(b[16:]),
		Netns: le.Uint32(b[24:]), Ifindex: le.Uint32(b[28:]), Reason: le.Uint32(b[32:]),
		Sport: le.Uint16(b[36:]), Kind: b[38], TTL: b[39], Src: b[40], Dst: b[41], FromMap: b[42],
	}, nil
}

func ensureTracefs() (bool, error) {
	for _, p := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		if _, err := os.Stat(p); err == nil {
			return false, nil
		}
	}
	return true, unix.Mount("nodev", "/sys/kernel/tracing", "tracefs", 0, "")
}

func dropReasonNames() map[uint32]string {
	m := map[uint32]string{}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return m
	}
	var e *btf.Enum
	if spec.TypeByName("skb_drop_reason", &e) == nil {
		for _, v := range e.Values {
			m[uint32(v.Value)] = strings.TrimPrefix(v.Name, "SKB_DROP_REASON_")
		}
	}
	return m
}

func main() {
	nsmap := nsFlags{}
	flag.Var(nsmap, "ns", "name=/proc/<pid>/ns/net (repeatable)")
	outPath := flag.String("out", "-", "output JSONL (- = stdout)")
	ready := flag.String("ready", "", "file to create once attached")
	flag.Parse()

	mounted, err := ensureTracefs()
	if err != nil {
		fail(fmt.Errorf("mount tracefs: %w", err))
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fail(err)
	}
	spec, err := loadTracer()
	if err != nil {
		fail(err)
	}
	if err := spec.Variables["probe_port"].Set(probe.Port); err != nil {
		fail(err)
	}
	var objs tracerObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		fail(fmt.Errorf("load: %w", err))
	}
	defer objs.Close()
	lr, err := link.Tracepoint("net", "netif_receive_skb", objs.TpRx, nil)
	if err != nil {
		fail(err)
	}
	defer lr.Close()
	ld, err := link.Tracepoint("skb", "kfree_skb", objs.TpDrop, nil)
	if err != nil {
		fail(err)
	}
	defer ld.Close()
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fail(err)
	}

	f := os.Stdout
	if *outPath != "-" {
		if f, err = os.Create(*outPath); err != nil {
			fail(err)
		}
	}
	w := bufio.NewWriterSize(f, 1<<20)
	reasons := dropReasonNames()
	names := map[uint32]string(nsmap)
	start := mono.Now()
	hdr, _ := json.Marshal(map[string]any{"kind": "start", "t": start, "tracefs_mounted_by_tracer": mounted,
		"netns": names, "drop_reason_names": "kernel BTF enum skb_drop_reason"})
	w.Write(append(hdr, '\n'))
	w.Flush()
	if *ready != "" {
		os.WriteFile(*ready, []byte("ok\n"), 0o644)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		// Let events already in the ring buffer drain, then stop.
		rd.SetDeadline(time.Now().Add(300 * time.Millisecond))
	}()

	var n, bad, unknownNs uint64
	var line []byte
	for {
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			fail(err)
		}
		e, err := decode(rec.RawSample)
		if err != nil {
			bad++
			continue
		}
		n++
		node, ok := names[e.Netns]
		if !ok {
			unknownNs++
			node = "ns:" + strconv.FormatUint(uint64(e.Netns), 10)
		}
		line = line[:0]
		line = append(line, `{"t":`...)
		line = strconv.AppendUint(line, e.TsNs, 10)
		if e.Kind == 0 {
			line = append(line, `,"ev":"rx"`...)
		} else {
			line = append(line, `,"ev":"drop","reason":`...)
			line = strconv.AppendUint(line, uint64(e.Reason), 10)
			line = append(line, `,"reason_name":`...)
			line = strconv.AppendQuote(line, reasons[e.Reason])
			line = append(line, `,"location":`...)
			line = strconv.AppendUint(line, e.Location, 10)
			if e.FromMap == 1 {
				line = append(line, `,"node_from":"last_rx"`...)
			}
		}
		line = append(line, `,"node":`...)
		line = strconv.AppendQuote(line, node)
		line = append(line, `,"ifindex":`...)
		line = strconv.AppendUint(line, uint64(e.Ifindex), 10)
		line = append(line, `,"ttl":`...)
		line = strconv.AppendUint(line, uint64(e.TTL), 10)
		line = append(line, `,"src":`...)
		line = strconv.AppendUint(line, uint64(e.Src), 10)
		line = append(line, `,"dst":`...)
		line = strconv.AppendUint(line, uint64(e.Dst), 10)
		line = append(line, `,"sp":`...)
		line = strconv.AppendUint(line, uint64(e.Sport), 10)
		line = append(line, `,"seq":`...)
		line = strconv.AppendUint(line, e.Seq, 10)
		line = append(line, '}', '\n')
		w.Write(line)
	}

	// Per-CPU counters: [0] written, [1] failed reservations.
	sum := func(i uint32) uint64 {
		var vals []uint64
		if err := objs.Counters.Lookup(&i, &vals); err != nil {
			fail(err)
		}
		var s uint64
		for _, v := range vals {
			s += v
		}
		return s
	}
	written, lost := sum(0), sum(1)
	valid := lost == 0 && bad == 0
	reason := ""
	if !valid {
		reason = fmt.Sprintf("%d ring-buffer reservations failed, %d undecodable events", lost, bad)
	}
	st, _ := json.Marshal(map[string]any{"kind": "stats", "t": mono.Now(), "events_read": n,
		"events_written": written, "ringbuf_lost": lost, "undecodable": bad,
		"unknown_netns_events": unknownNs, "valid": valid, "invalid_reason": reason})
	w.Write(append(st, '\n'))
	w.Flush()
	rd.Close()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "tracer:", err)
	os.Exit(2)
}
