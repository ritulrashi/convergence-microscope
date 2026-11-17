//go:build linux

// Command lagprobe attaches bpf/lag.bpf.c kprobes (rtnl_notify,
// fib_table_insert, fib_table_delete) for one network namespace and writes
// one JSON line per call, stamped with CLOCK_MONOTONIC. E0 compares these
// with the recorder's receipt times to bound the recorder's lag.
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
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target bpfel lag ../../../bpf/lag.bpf.c -- -I../../../bpf

var fnName = []string{"rtnl_notify", "fib_table_insert", "fib_table_delete"}

func main() {
	netns := flag.String("netns", "", "network namespace path")
	out := flag.String("out", "-", "output JSONL")
	ready := flag.String("ready", "", "file to create once attached")
	flag.Parse()
	var st unix.Stat_t
	if err := unix.Stat(*netns, &st); err != nil {
		fail(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fail(err)
	}
	spec, err := loadLag()
	if err != nil {
		fail(err)
	}
	if err := spec.Variables["filter_netns"].Set(uint32(st.Ino)); err != nil {
		fail(err)
	}
	var objs lagObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		fail(err)
	}
	defer objs.Close()
	attached := map[string]bool{}
	if l, err := link.Kprobe("rtnl_notify", objs.K_notify, nil); err == nil {
		defer l.Close()
		attached["rtnl_notify"] = true
	}
	if l, err := link.Kprobe("fib_table_insert", objs.K_insert, nil); err == nil {
		defer l.Close()
		attached["fib_table_insert"] = true
	}
	if l, err := link.Kprobe("fib_table_delete", objs.K_delete, nil); err == nil {
		defer l.Close()
		attached["fib_table_delete"] = true
	}
	if len(attached) == 0 {
		fail(errors.New("no kprobe could be attached"))
	}
	rd, err := ringbuf.NewReader(objs.LagEvents)
	if err != nil {
		fail(err)
	}
	f := os.Stdout
	if *out != "-" {
		if f, err = os.Create(*out); err != nil {
			fail(err)
		}
	}
	w := bufio.NewWriter(f)
	hdr, _ := json.Marshal(map[string]any{"kind": "start", "attached": attached, "netns": st.Ino})
	w.Write(append(hdr, '\n'))
	w.Flush()
	if *ready != "" {
		os.WriteFile(*ready, []byte("ok\n"), 0o644)
	}
	var stopping atomic.Bool
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() { <-sig; stopping.Store(true) }()
	for {
		rd.SetDeadline(time.Now().Add(200 * time.Millisecond))
		rec, err := rd.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if stopping.Load() {
				break
			}
			continue
		}
		if err != nil {
			fail(err)
		}
		b := rec.RawSample
		if len(b) < 16 {
			continue
		}
		fn := binary.LittleEndian.Uint32(b[8:])
		name := "?"
		if int(fn) < len(fnName) {
			name = fnName[fn]
		}
		line, _ := json.Marshal(map[string]any{"kind": "call", "t": binary.LittleEndian.Uint64(b[0:]),
			"fn": name, "group": binary.LittleEndian.Uint32(b[12:])})
		w.Write(append(line, '\n'))
	}
	var z uint32
	var lost uint64
	objs.LagLost.Lookup(&z, &lost)
	end, _ := json.Marshal(map[string]any{"kind": "stats", "lost": lost, "valid": lost == 0})
	w.Write(append(end, '\n'))
	w.Flush()
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "lagprobe:", err)
	os.Exit(2)
}
