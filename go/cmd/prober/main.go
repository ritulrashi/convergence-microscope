// Command prober sends and receives UDP probes on a lab host.
//
// One process runs per host. It listens on probe.Port and, for every
// destination given with -dst, sends -rate packets per second on a fixed
// schedule (packet seq is due at start + seq/rate), rotating the source port
// through -ports so a (src, dst) pair covers several ECMP paths. Every sent
// and received packet is logged as one JSON line; a final stats line says
// whether the run is valid (the send schedule never slipped more than
// -tolerance).
//
// All prober processes in a run get the same -start-at, a CLOCK_MONOTONIC
// timestamp. Containers share the kernel, so they start together.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"

	"github.com/ritulrashi/convergence-microscope/go/internal/mono"
	"github.com/ritulrashi/convergence-microscope/go/internal/probe"
)

type dest struct {
	id uint8
	ip net.IP
}

type logger struct {
	mu sync.Mutex
	w  *bufio.Writer
}

func (l *logger) line(v any) {
	b, _ := json.Marshal(v)
	l.mu.Lock()
	l.w.Write(b)
	l.w.WriteByte('\n')
	l.mu.Unlock()
}

type sendRec struct {
	K   string `json:"k"`
	Src uint8  `json:"src"`
	Dst uint8  `json:"dst"`
	Sp  uint16 `json:"sp"`
	Seq uint64 `json:"seq"`
	T   int64  `json:"t"`
}

type recvRec struct {
	K   string `json:"k"`
	Src uint8  `json:"src"`
	Dst uint8  `json:"dst"`
	Sp  uint16 `json:"sp"`
	Seq uint64 `json:"seq"`
	Ts  int64  `json:"ts"`
	T   int64  `json:"t"`
	TTL int    `json:"ttl"`
}

type stats struct {
	K             string `json:"k"`
	ID            uint8  `json:"id"`
	Rate          int    `json:"rate_pps"`
	StartNs       int64  `json:"start_ns"`
	DurationNs    int64  `json:"duration_ns"`
	Sent          uint64 `json:"sent"`
	SendErrors    uint64 `json:"send_errors"`
	Recv          uint64 `json:"recv"`
	RecvBad       uint64 `json:"recv_bad"`
	MaxLateNs     int64  `json:"max_late_ns"`
	LateOverTol   uint64 `json:"late_over_tolerance"`
	ToleranceNs   int64  `json:"tolerance_ns"`
	Valid         bool   `json:"valid"`
	InvalidReason string `json:"invalid_reason,omitempty"`
}

func main() {
	id := flag.Uint("id", 0, "this host's id (1..255)")
	dsts := flag.String("dst", "", "destinations: id=ip,id=ip (empty: receive only)")
	rate := flag.Int("rate", 1000, "packets per second per destination")
	ports := flag.String("ports", "40000,40001,40002,40003", "source ports to rotate through")
	startAt := flag.Int64("start-at", 0, "CLOCK_MONOTONIC ns to start sending (0: now+200ms)")
	dur := flag.Duration("duration", 10*time.Second, "sending duration")
	grace := flag.Duration("grace", 2*time.Second, "keep receiving this long after sending ends")
	tol := flag.Duration("tolerance", 5*time.Millisecond, "max allowed lateness of any send")
	out := flag.String("out", "-", "output JSONL path (- = stdout)")
	flag.Parse()

	if *id == 0 || *id > 255 || *rate <= 0 {
		fail(errors.New("need -id in 1..255 and -rate > 0"))
	}
	ds, err := parseDests(*dsts)
	if err != nil {
		fail(err)
	}
	ps, err := parsePorts(*ports)
	if err != nil {
		fail(err)
	}
	f := os.Stdout
	if *out != "-" {
		if f, err = os.Create(*out); err != nil {
			fail(err)
		}
	}
	lg := &logger{w: bufio.NewWriterSize(f, 1<<20)}

	rc, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(probe.Port)})
	if err != nil {
		fail(err)
	}
	pc := ipv4.NewPacketConn(rc)
	if err := pc.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		fail(err)
	}
	socks := map[uint16]*net.UDPConn{}
	for _, p := range ps {
		c, err := net.ListenUDP("udp4", &net.UDPAddr{Port: int(p)})
		if err != nil {
			fail(err)
		}
		socks[p] = c
	}

	st := stats{K: "stats", ID: uint8(*id), Rate: *rate, DurationNs: dur.Nanoseconds(), ToleranceNs: tol.Nanoseconds()}
	if *startAt == 0 {
		*startAt = mono.Now() + 200*int64(time.Millisecond)
	}
	st.StartNs = *startAt
	end := *startAt + dur.Nanoseconds()

	var recv, recvBad atomic.Uint64
	go func() {
		buf := make([]byte, 2048)
		for {
			n, cm, _, err := pc.ReadFrom(buf)
			t := mono.Now()
			if err != nil {
				return
			}
			p, err := probe.Decode(buf[:n])
			if err != nil {
				recvBad.Add(1)
				continue
			}
			ttl := -1
			if cm != nil {
				ttl = cm.TTL
			}
			recv.Add(1)
			lg.line(recvRec{"r", p.Src, p.Dst, p.Sport, p.Seq, p.SentNs, t, ttl})
		}
	}()

	var sent, sendErr, lateOver atomic.Uint64
	var maxLate atomic.Int64
	var wg sync.WaitGroup
	interval := int64(time.Second) / int64(*rate)
	for _, d := range ds {
		wg.Add(1)
		go func(d dest) {
			defer wg.Done()
			sch := probe.Schedule{StartNs: *startAt, IntervalNs: interval, Ports: ps}
			addr := &net.UDPAddr{IP: d.ip, Port: int(probe.Port)}
			buf := make([]byte, probe.Size)
			for seq := uint64(0); ; seq++ {
				due := sch.Due(seq)
				if due >= end {
					return
				}
				if wait := due - mono.Now(); wait > 0 {
					time.Sleep(time.Duration(wait))
				}
				now := mono.Now()
				late := now - due
				for {
					m := maxLate.Load()
					if late <= m || maxLate.CompareAndSwap(m, late) {
						break
					}
				}
				if late > tol.Nanoseconds() {
					lateOver.Add(1)
				}
				sp := sch.Port(seq)
				b := probe.Probe{Src: uint8(*id), Dst: d.id, Sport: sp, Seq: seq, SentNs: now}.Encode(buf)
				if _, err := socks[sp].WriteToUDP(b, addr); err != nil {
					sendErr.Add(1)
				}
				sent.Add(1)
				lg.line(sendRec{"s", uint8(*id), d.id, sp, seq, now})
			}
		}(d)
	}
	wg.Wait()
	if wait := end + grace.Nanoseconds() - mono.Now(); wait > 0 {
		time.Sleep(time.Duration(wait))
	}
	rc.Close()

	st.Sent, st.SendErrors, st.Recv, st.RecvBad = sent.Load(), sendErr.Load(), recv.Load(), recvBad.Load()
	st.MaxLateNs, st.LateOverTol = maxLate.Load(), lateOver.Load()
	st.Valid = st.LateOverTol == 0
	if !st.Valid {
		st.InvalidReason = fmt.Sprintf("%d sends later than %s (max %s)", st.LateOverTol, *tol, time.Duration(st.MaxLateNs))
	}
	lg.line(st)
	if err := lg.w.Flush(); err != nil {
		fail(err)
	}
	if f != os.Stdout {
		f.Close()
	}
}

func parseDests(s string) ([]dest, error) {
	var out []dest
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		k, v, ok := strings.Cut(part, "=")
		n, err := strconv.Atoi(k)
		ip := net.ParseIP(v).To4()
		if !ok || err != nil || n < 1 || n > 255 || ip == nil {
			return nil, fmt.Errorf("bad -dst entry %q", part)
		}
		out = append(out, dest{uint8(n), ip})
	}
	return out, nil
}

func parsePorts(s string) ([]uint16, error) {
	var out []uint16
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(part)
		if err != nil || n < 1024 || n > 65535 || n == int(probe.Port) {
			return nil, fmt.Errorf("bad port %q", part)
		}
		out = append(out, uint16(n))
	}
	if len(out) == 0 {
		return nil, errors.New("no ports")
	}
	return out, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "prober:", err)
	os.Exit(2)
}
