// Command replay rebuilds a run's forwarding state from the recorder's events
// and predicts every probe packet's fate, then checks the predictions against
// what the packets did.
//
// Input, in -run DIR: plan.json (lab plan), fib_events.jsonl (recorder),
// probes.jsonl (prober), and, in Tier A, hops.jsonl (tracer); plus
// -reasons (results/calibration/drop_reasons.json) to classify drops.
//
// Output, in DIR/replay/: predictions.jsonl (one line per probe that was not
// delivered, or whose prediction was not "delivered"), mismatches.jsonl,
// loops.jsonl (forwarding loops in F, per destination) and summary.json with
// the two validation metrics:
//
//	path consistency: share of observed hop transitions F allowed at that time
//	fate agreement:   among non-ambiguous predictions, share matching observation
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/ritulrashi/convergence-microscope/go/internal/replay"
)

type plan struct {
	Routers []struct {
		Name     string `json:"name"`
		Loopback string `json:"loopback"`
		Ifaces   []struct {
			Address string `json:"address"`
		} `json:"ifaces"`
	} `json:"routers"`
	Hosts []struct {
		Name    string `json:"name"`
		Router  string `json:"router"`
		Site    int    `json:"site"`
		Address string `json:"address"`
	} `json:"hosts"`
}

type reasons struct {
	Blackhole  []string `json:"blackhole"` // "code@function"
	TTLExpired []string `json:"ttl_expired"`
}

type probeKey struct {
	Src, Dst uint8
	Seq      uint64
}

type send struct {
	Sp uint16
	T  int64
}

type hop struct {
	T          int64  `json:"t"`
	Ev         string `json:"ev"`
	Node       string `json:"node"`
	TTL        int    `json:"ttl"`
	Reason     uint32 `json:"reason"`
	ReasonName string `json:"reason_name"`
	Location   string `json:"location"`
}

func main() {
	run := flag.String("run", "", "run directory")
	reasonsPath := flag.String("reasons", "results/calibration/drop_reasons.json", "calibrated drop-reason codes")
	ttl := flag.Int("ttl", 64, "TTL probes have when they reach the first router")
	flag.Parse()
	if *run == "" {
		fail(fmt.Errorf("need -run"))
	}
	var pl plan
	readJSON(filepath.Join(*run, "plan.json"), &pl)
	var rs reasons
	readJSON(*reasonsPath, &rs)
	bhCodes, ttlCodes := set(rs.Blackhole), set(rs.TTLExpired)

	// Topology: every interface address and loopback names its node.
	tp := &replay.Topo{AddrNode: map[netip.Addr]string{}, Hosts: map[string]replay.Host{}}
	hostByID := map[uint8]string{}
	for _, r := range pl.Routers {
		tp.AddrNode[addr(r.Loopback)] = r.Name
		for _, i := range r.Ifaces {
			tp.AddrNode[addr(i.Address)] = r.Name
		}
	}
	for _, h := range pl.Hosts {
		a := addr(h.Address)
		tp.AddrNode[a] = h.Name
		tp.Hosts[h.Name] = replay.Host{Addr: a, Gateway: h.Router}
		hostByID[uint8(h.Site)] = h.Name
	}
	// Router interface addresses on host subnets (gateways) belong to routers.
	for _, r := range pl.Routers {
		for _, i := range r.Ifaces {
			tp.AddrNode[addr(i.Address)] = r.Name
		}
	}

	// FIB from the recorder: init records are each router's starting state.
	fib := replay.NewFIB()
	var fibStart, fibEnd int64
	eachLine(filepath.Join(*run, "fib_events.jsonl"), func(b []byte) {
		var e struct {
			Kind, Router, Prefix string
			T                    int64
			New                  []string
		}
		must(json.Unmarshal(b, &e))
		if e.Kind != "init" && e.Kind != "fib" {
			return
		}
		p, err := netip.ParsePrefix(e.Prefix)
		must(err)
		fib.Add(e.Router, p, e.T, e.New)
		if fibStart == 0 || e.T < fibStart {
			fibStart = e.T
		}
		fibEnd = max(fibEnd, e.T)
	})
	fib.Sort()

	// Probes.
	sends := map[probeKey]send{}
	recvs := map[probeKey]int64{}
	var lastSend int64
	eachLine(filepath.Join(*run, "probes.jsonl"), func(b []byte) {
		var x struct {
			K        string
			Src, Dst uint8
			Sp       uint16
			Seq      uint64
			T        int64
		}
		must(json.Unmarshal(b, &x))
		k := probeKey{x.Src, x.Dst, x.Seq}
		switch x.K {
		case "s":
			sends[k] = send{x.Sp, x.T}
			lastSend = max(lastSend, x.T)
		case "r":
			if _, dup := recvs[k]; !dup {
				recvs[k] = x.T
			}
		}
	})

	// Hops (Tier A).
	hopsPath := filepath.Join(*run, "hops.jsonl")
	tierA := exists(hopsPath)
	hops := map[probeKey][]hop{}
	if tierA {
		eachLine(hopsPath, func(b []byte) {
			var x struct {
				hop
				Src, Dst uint8
				Seq      uint64
			}
			must(json.Unmarshal(b, &x))
			if x.Ev == "" {
				return
			}
			k := probeKey{x.Src, x.Dst, x.Seq}
			hops[k] = append(hops[k], x.hop)
		})
		for k := range hops {
			hs := hops[k]
			sort.Slice(hs, func(i, j int) bool { return hs[i].T < hs[j].T })
		}
	}

	perHop := perHopLatency(sends, recvs, hops, tierA)

	outDir := filepath.Join(*run, "replay")
	must(os.MkdirAll(outDir, 0o755))
	predW := newJSONL(filepath.Join(outDir, "predictions.jsonl"))
	misW := newJSONL(filepath.Join(outDir, "mismatches.jsonl"))

	keys := make([]probeKey, 0, len(sends))
	for k := range sends {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := sends[keys[i]], sends[keys[j]]
		if a.T != b.T {
			return a.T < b.T
		}
		return keys[i].Src < keys[j].Src || (keys[i].Src == keys[j].Src && keys[i].Dst < keys[j].Dst)
	})

	predCount := map[replay.Fate]int{}
	obsCount := map[string]int{}
	var agreeN, agreeOK, transN, transOK int
	mismatchClass := map[string]int{}
	lossByCause := map[string]int{}
	for _, k := range keys {
		s := sends[k]
		dstName, srcName := hostByID[k.Dst], hostByID[k.Src]
		dh, okD := tp.Hosts[dstName]
		sh, okS := tp.Hosts[srcName]
		if !okD || !okS {
			continue
		}
		// Observed.
		obs := "lost"
		var path []hop
		if _, ok := recvs[k]; ok {
			obs = "delivered"
		}
		ht := replay.HopTimes{SendNs: s.T, PerHopNs: perHop}
		if tierA {
			path = hops[k]
			for _, h := range path {
				if h.Ev == "rx" && h.Node != dstName {
					ht.Observed = append(ht.Observed, h.T)
				}
			}
			if obs == "lost" {
				obs = "unknown"
				for _, h := range path {
					if h.Ev == "drop" {
						switch {
						case bhCodes[dropKey(h)]:
							obs = "blackhole"
						case ttlCodes[dropKey(h)]:
							obs = "loop"
						default:
							obs = "other:" + h.ReasonName
						}
					}
				}
			}
			// Path consistency over observed router-to-next-node transitions.
			for i := 0; i+1 < len(path); i++ {
				a, b := path[i], path[i+1]
				if a.Ev != "rx" || b.Ev != "rx" || a.Node == dstName {
					continue
				}
				transN++
				if replay.Allowed(fib, tp, a.Node, b.Node, dh.Addr, a.T) {
					transOK++
				}
			}
		}
		obsCount[obs]++
		if obs != "delivered" {
			lossByCause[obs]++
		}

		p := replay.Predict(fib, tp, sh.Gateway, dh.Addr, *ttl, ht)
		predCount[p.Fate]++
		match := false
		if p.Fate != replay.Ambiguous {
			agreeN++
			match = string(p.Fate) == obs || (!tierA && p.Fate != replay.Delivered && obs == "lost")
			if match {
				agreeOK++
			}
		}
		if obs == "delivered" && p.Fate == replay.Delivered {
			continue
		}
		rec := map[string]any{
			"src": srcName, "dst": dstName, "sp": s.Sp, "seq": k.Seq, "t_send": s.T,
			"predicted": p.Fate, "branches": p.Branches, "blackhole_at": p.BlackholeAt,
			"loop_at": p.LoopNodes, "observed": obs, "match": match,
		}
		if tierA {
			rec["path"] = pathSummary(path)
		}
		predW.write(rec)
		if p.Fate != replay.Ambiguous && !match {
			cls := classify(fib, p, obs, ht, path)
			mismatchClass[cls]++
			rec["class"] = cls
			rec["nearest_fib_change_ns"] = nearestChange(fib, s.T)
			misW.write(rec)
		}
	}
	predW.close()
	misW.close()

	// Loops in F, per destination host, over the run.
	var dsts []netip.Addr
	for _, h := range pl.Hosts {
		dsts = append(dsts, addr(h.Address))
	}
	sort.Slice(dsts, func(i, j int) bool { return dsts[i].Less(dsts[j]) })
	loopW := newJSONL(filepath.Join(outDir, "loops.jsonl"))
	loops := replay.Loops(fib, tp, dsts, fibStart, max(fibEnd, lastSend))
	for _, l := range loops {
		loopW.write(map[string]any{"dst": l.Dst.String(), "routers": l.Routers, "start": l.Start,
			"end": l.End, "duration_ns": l.DurationNs()})
	}
	loopW.close()

	sum := map[string]any{
		"tier":               map[bool]string{true: "A", false: "B"}[tierA],
		"probes":             len(keys),
		"per_hop_latency_ns": perHop,
		"predicted":          predCount,
		"observed":           obsCount,
		"lost_by_cause":      lossByCause,
		"fate_agreement":     ratio(agreeOK, agreeN),
		"fate_agreement_n":   agreeN,
		"mismatch_classes":   mismatchClass,
		"fib_loops":          len(loops),
	}
	if tierA {
		sum["path_consistency"] = ratio(transOK, transN)
		sum["path_transitions"] = transN
	} else {
		sum["cause_attribution"] = "predicted, not observed"
	}
	b, _ := json.MarshalIndent(sum, "", "  ")
	must(os.WriteFile(filepath.Join(outDir, "summary.json"), append(b, '\n'), 0o644))
	fmt.Println(string(b))
}

// classify gives a first, automatic label to a mismatch; FINDINGS.md
// reviews them. near-change: a FIB change at a router on the predicted or
// observed path within 5 ms of the probe's hop times (recorder lag or
// timing); model: otherwise.
func classify(f *replay.FIB, p replay.Prediction, obs string, ht replay.HopTimes, path []hop) string {
	if strings.HasPrefix(obs, "other:") || obs == "unknown" {
		return "observed-" + strings.SplitN(obs, ":", 2)[0]
	}
	t0, t1 := ht.At(0), ht.At(len(ht.Observed)+2)
	for _, c := range f.ChangeTimes() {
		if c >= t0-5_000_000 && c <= t1+5_000_000 {
			return "near-fib-change"
		}
	}
	return "model"
}

func nearestChange(f *replay.FIB, t int64) int64 {
	best := int64(-1)
	for _, c := range f.ChangeTimes() {
		d := c - t
		if d < 0 {
			d = -d
		}
		if best < 0 || d < best {
			best = d
		}
	}
	return best
}

func pathSummary(p []hop) []string {
	out := make([]string, 0, len(p))
	for _, h := range p {
		s := h.Node
		if h.Ev == "drop" {
			s = "DROP(" + h.ReasonName + ")@" + h.Node
		}
		out = append(out, s)
	}
	return out
}

// perHopLatency: Tier A, the median gap between consecutive rx events of one
// probe; Tier B, the median one-way delay divided by 4 (the T1 and T2
// shortest paths are 2 to 4 router hops; see DESIGN.md).
func perHopLatency(sends map[probeKey]send, recvs map[probeKey]int64, hops map[probeKey][]hop, tierA bool) int64 {
	var xs []int64
	if tierA {
		for _, hs := range hops {
			for i := 0; i+1 < len(hs); i++ {
				if hs[i].Ev == "rx" && hs[i+1].Ev == "rx" {
					xs = append(xs, hs[i+1].T-hs[i].T)
				}
			}
		}
	} else {
		for k, t := range recvs {
			if s, ok := sends[k]; ok {
				xs = append(xs, (t-s.T)/4)
			}
		}
	}
	if len(xs) == 0 {
		return 20_000
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i] < xs[j] })
	return xs[len(xs)/2]
}

func ratio(a, b int) any {
	if b == 0 {
		return nil
	}
	return float64(a) / float64(b)
}

func dropKey(h hop) string { return strconv.FormatUint(uint64(h.Reason), 10) + "@" + h.Location }

func set(xs []string) map[string]bool {
	m := map[string]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func addr(s string) netip.Addr {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr()
	}
	a, err := netip.ParseAddr(s)
	must(err)
	return a
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func readJSON(path string, v any) {
	b, err := os.ReadFile(path)
	must(err)
	must(json.Unmarshal(b, v))
}

func eachLine(path string, fn func([]byte)) {
	f, err := os.Open(path)
	must(err)
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		if len(strings.TrimSpace(sc.Text())) > 0 {
			fn(sc.Bytes())
		}
	}
	must(sc.Err())
}

type jsonl struct {
	f *os.File
	w *bufio.Writer
}

func newJSONL(path string) *jsonl {
	f, err := os.Create(path)
	must(err)
	return &jsonl{f, bufio.NewWriter(f)}
}

func (j *jsonl) write(v any) {
	b, _ := json.Marshal(v)
	j.w.Write(append(b, '\n'))
}

func (j *jsonl) close() { j.w.Flush(); j.f.Close() }

func must(err error) {
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "replay:", err)
	os.Exit(2)
}
