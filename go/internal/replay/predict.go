package replay

import (
	"net/netip"
	"sort"
	"strings"
)

// Fate is a packet's outcome class.
type Fate string

const (
	Delivered Fate = "delivered"
	Blackhole Fate = "blackhole" // a router had no usable route
	Loop      Fate = "loop"      // TTL ran out inside the fabric
	Ambiguous Fate = "ambiguous" // ECMP branches disagree
)

// Topo maps next-hop strings to nodes.
type Topo struct {
	// AddrNode maps every router and host interface address to its node.
	AddrNode map[netip.Addr]string
	// Hosts maps host name to its address and first-hop router.
	Hosts map[string]Host
}

type Host struct {
	Addr    netip.Addr
	Gateway string // first-hop router
}

// HopTimes gives the time a probe reaches its k-th router (k = 0 is the
// first-hop router). Tier A fills it from observed rx events; beyond the
// observed hops, and in Tier B, times advance by PerHopNs.
type HopTimes struct {
	SendNs   int64
	Observed []int64 // observed arrival times at hop 0, 1, ...
	PerHopNs int64
}

func (h HopTimes) At(k int) int64 {
	if k < len(h.Observed) {
		return h.Observed[k]
	}
	if n := len(h.Observed); n > 0 {
		return h.Observed[n-1] + int64(k-n+1)*h.PerHopNs
	}
	return h.SendNs + int64(k+1)*h.PerHopNs
}

// Next resolves one next-hop string at a router for destination dst:
// the next node's name, or a terminal fate.
func (tp *Topo) Next(hop string, dst netip.Addr) (node string, fate Fate) {
	switch hop {
	case "blackhole", "unreachable", "prohibit":
		return "", Blackhole
	}
	gw, _, _ := strings.Cut(hop, "@")
	if gw == "direct" {
		// Connected subnet: delivered if dst is a host on it, else nobody answers.
		if n, ok := tp.AddrNode[dst]; ok {
			if _, isHost := tp.Hosts[n]; isHost {
				return n, Delivered
			}
		}
		return "", Blackhole
	}
	a, err := netip.ParseAddr(gw)
	if err != nil {
		return "", Blackhole
	}
	n, ok := tp.AddrNode[a]
	if !ok {
		return "", Blackhole
	}
	if _, isHost := tp.Hosts[n]; isHost {
		return n, Delivered
	}
	return n, ""
}

// Prediction is the set-level outcome of one probe.
type Prediction struct {
	Fate Fate
	// Branches counts terminal outcomes over all ECMP branches (by state, not
	// by path, so it is a presence count rather than a probability).
	Branches map[Fate]int
	// Where names the routers at which blackhole branches ended.
	BlackholeAt []string
	// LoopNodes names the routers where TTL ran out.
	LoopNodes []string
}

// Predict walks every ECMP branch of a probe from its first-hop router,
// reading F at each hop's arrival time. ttl is the TTL the first router
// receives (64 from a Linux host).
func Predict(f *FIB, tp *Topo, firstHop string, dst netip.Addr, ttl int, ht HopTimes) Prediction {
	type state struct {
		node string
		k    int
	}
	seen := map[state]bool{}
	out := Prediction{Branches: map[Fate]int{}}
	bh, lp := map[string]bool{}, map[string]bool{}
	stack := []state{{firstHop, 0}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[s] {
			continue
		}
		seen[s] = true
		// The router receives TTL ttl-k; it forwards only if that is > 1.
		if ttl-s.k <= 1 {
			out.Branches[Loop]++
			lp[s.node] = true
			continue
		}
		set, _ := f.Lookup(s.node, dst, ht.At(s.k))
		if len(set) == 0 {
			out.Branches[Blackhole]++
			bh[s.node] = true
			continue
		}
		for _, hop := range set {
			n, fate := tp.Next(hop, dst)
			switch fate {
			case Delivered:
				out.Branches[Delivered]++
			case Blackhole:
				out.Branches[Blackhole]++
				bh[s.node] = true
			default:
				stack = append(stack, state{n, s.k + 1})
			}
		}
	}
	out.BlackholeAt, out.LoopNodes = keys(bh), keys(lp)
	switch {
	case len(out.Branches) == 1:
		for k := range out.Branches {
			out.Fate = k
		}
	default:
		out.Fate = Ambiguous
	}
	return out
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Allowed reports whether moving from router a to node b at time t is
// allowed by F (one of a's next hops for dst resolves to b).
func Allowed(f *FIB, tp *Topo, a, b string, dst netip.Addr, t int64) bool {
	set, _ := f.Lookup(a, dst, t)
	for _, hop := range set {
		if n, _ := tp.Next(hop, dst); n == b {
			return true
		}
	}
	return false
}
