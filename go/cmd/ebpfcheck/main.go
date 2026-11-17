// Command ebpfcheck loads bpf/calib.bpf.c, attaches it to the
// netif_receive_skb and kfree_skb tracepoints, and reports what it saw.
//
// It is used by scripts/preflight.sh (can eBPF attach from inside the
// devcontainer, and does it see packets in a containerlab node's netns?) and
// by calibration (which drop-reason codes does this kernel emit?).
package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall" -target bpfel calib ../../../bpf/calib.bpf.c -- -I../../../bpf

type countRow struct {
	Tracepoint string `json:"tracepoint"`
	Netns      uint32 `json:"netns"`
	Count      uint64 `json:"count"`
}

type reasonRow struct {
	Code  uint32 `json:"code"`
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type report struct {
	Attached     map[string]bool `json:"attached"`
	Error        string          `json:"error,omitempty"`
	DurationS    float64         `json:"duration_s"`
	TargetNetns  uint32          `json:"target_netns"`
	TargetRecv   uint64          `json:"target_recv"`
	TargetDrop   uint64          `json:"target_drop"`
	Counts       []countRow      `json:"counts"`
	DropReasons  []reasonRow     `json:"drop_reasons"`
	RingbufLost  uint64          `json:"ringbuf_lost"`
	ReasonSource string          `json:"reason_names_source"`
}

func main() {
	netns := flag.Uint("netns", 0, "network-namespace inode to watch for drop events (0 = none)")
	dur := flag.Duration("duration", 5*time.Second, "how long to collect")
	out := flag.String("out", "-", "output JSON path (- = stdout)")
	ready := flag.String("ready", "", "file to create once attached")
	flag.Parse()

	r := report{Attached: map[string]bool{"netif_receive_skb": false, "kfree_skb": false}, TargetNetns: uint32(*netns)}
	err := run(&r, uint32(*netns), *dur, *ready)
	if err != nil {
		r.Error = err.Error()
	}
	if werr := write(*out, r); werr != nil {
		fmt.Fprintln(os.Stderr, werr)
		os.Exit(2)
	}
	if err != nil {
		os.Exit(1)
	}
}

func run(r *report, netns uint32, dur time.Duration, ready string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	spec, err := loadCalib()
	if err != nil {
		return fmt.Errorf("load spec: %w", err)
	}
	if err := spec.Variables["filter_netns"].Set(netns); err != nil {
		return fmt.Errorf("set filter: %w", err)
	}
	var objs calibObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return fmt.Errorf("load objects: %w", err)
	}
	defer objs.Close()

	lr, err := link.Tracepoint("net", "netif_receive_skb", objs.TpRecv, nil)
	if err != nil {
		return fmt.Errorf("attach netif_receive_skb: %w", err)
	}
	defer lr.Close()
	r.Attached["netif_receive_skb"] = true
	ld, err := link.Tracepoint("skb", "kfree_skb", objs.TpDrop, nil)
	if err != nil {
		return fmt.Errorf("attach kfree_skb: %w", err)
	}
	defer ld.Close()
	r.Attached["kfree_skb"] = true

	rd, err := ringbuf.NewReader(objs.Drops)
	if err != nil {
		return fmt.Errorf("ringbuf: %w", err)
	}
	defer rd.Close()

	if ready != "" {
		if err := os.WriteFile(ready, []byte("ok\n"), 0o644); err != nil {
			return err
		}
	}

	byReason := map[uint32]uint64{}
	start := time.Now()
	rd.SetDeadline(start.Add(dur))
	for {
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			break
		}
		if err != nil {
			return fmt.Errorf("ringbuf read: %w", err)
		}
		// struct drop_event: ts u64, netns u32, ifindex u32, reason u32, ...
		if len(rec.RawSample) >= 20 {
			byReason[binary.LittleEndian.Uint32(rec.RawSample[16:20])]++
		}
	}
	r.DurationS = time.Since(start).Seconds()

	var k struct{ Tp, Netns uint32 }
	var v uint64
	it := objs.Counts.Iterate()
	for it.Next(&k, &v) {
		name := "netif_receive_skb"
		if k.Tp == 1 {
			name = "kfree_skb"
		}
		r.Counts = append(r.Counts, countRow{name, k.Netns, v})
		if k.Netns == netns && netns != 0 {
			if k.Tp == 0 {
				r.TargetRecv += v
			} else {
				r.TargetDrop += v
			}
		}
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate counts: %w", err)
	}
	sort.Slice(r.Counts, func(i, j int) bool { return r.Counts[i].Count > r.Counts[j].Count })

	var zero uint32
	if err := objs.Lost.Lookup(&zero, &r.RingbufLost); err != nil {
		return fmt.Errorf("lost lookup: %w", err)
	}

	names, src := dropReasonNames()
	r.ReasonSource = src
	for code, n := range byReason {
		r.DropReasons = append(r.DropReasons, reasonRow{code, names[code], n})
	}
	sort.Slice(r.DropReasons, func(i, j int) bool { return r.DropReasons[i].Code < r.DropReasons[j].Code })
	return nil
}

// dropReasonNames reads enum skb_drop_reason from the running kernel's BTF,
// so names always match this kernel instead of a hard-coded table.
func dropReasonNames() (map[uint32]string, string) {
	m := map[uint32]string{}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return m, "unavailable: " + err.Error()
	}
	var e *btf.Enum
	if err := spec.TypeByName("skb_drop_reason", &e); err != nil {
		return m, "unavailable: " + err.Error()
	}
	for _, v := range e.Values {
		m[uint32(v.Value)] = v.Name
	}
	return m, "kernel BTF enum skb_drop_reason"
}

func write(path string, r report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if path == "-" {
		_, err = os.Stdout.Write(b)
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
