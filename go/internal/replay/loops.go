package replay

import (
	"net/netip"
	"sort"
	"strings"
)

// LoopInterval is a forwarding loop for one destination that F contains
// from Start until End (End = the time F stopped containing it).
type LoopInterval struct {
	Dst     netip.Addr
	Routers []string
	Start   int64
	End     int64
}

func (l LoopInterval) DurationNs() int64 { return l.End - l.Start }

// cycles returns, for one destination at one time, every set of routers
// that forward into each other (strongly connected components with a cycle).
func cycles(f *FIB, tp *Topo, routers []string, dst netip.Addr, t int64) [][]string {
	adj := map[string][]string{}
	for _, r := range routers {
		set, _ := f.Lookup(r, dst, t)
		for _, hop := range set {
			if n, fate := tp.Next(hop, dst); fate == "" {
				adj[r] = append(adj[r], n)
			}
		}
	}
	// Tarjan's SCC.
	index, low := map[string]int{}, map[string]int{}
	on := map[string]bool{}
	var stack []string
	var out [][]string
	i := 0
	var visit func(v string)
	visit = func(v string) {
		index[v], low[v] = i, i
		i++
		stack = append(stack, v)
		on[v] = true
		for _, w := range adj[v] {
			if _, ok := index[w]; !ok {
				visit(w)
				low[v] = min(low[v], low[w])
			} else if on[w] {
				low[v] = min(low[v], index[w])
			}
		}
		if low[v] == index[v] {
			var comp []string
			for {
				w := stack[len(stack)-1]
				stack = stack[:len(stack)-1]
				on[w] = false
				comp = append(comp, w)
				if w == v {
					break
				}
			}
			self := false
			for _, w := range adj[v] {
				self = self || w == v
			}
			if len(comp) > 1 || self {
				sort.Strings(comp)
				out = append(out, comp)
			}
		}
	}
	for _, r := range routers {
		if _, ok := index[r]; !ok {
			visit(r)
		}
	}
	sort.Slice(out, func(a, b int) bool { return strings.Join(out[a], ",") < strings.Join(out[b], ",") })
	return out
}

// Loops sweeps F between from and to and returns every loop interval for
// each destination. A loop still present at `to` ends at `to`.
func Loops(f *FIB, tp *Topo, dsts []netip.Addr, from, to int64) []LoopInterval {
	routers := f.Routers()
	times := []int64{from}
	for _, t := range f.ChangeTimes() {
		if t > from && t < to {
			times = append(times, t)
		}
	}
	var out []LoopInterval
	for _, dst := range dsts {
		open := map[string]*LoopInterval{}
		for _, t := range times {
			now := map[string][]string{}
			for _, c := range cycles(f, tp, routers, dst, t) {
				now[strings.Join(c, ",")] = c
			}
			for k, li := range open {
				if _, still := now[k]; !still {
					li.End = t
					out = append(out, *li)
					delete(open, k)
				}
			}
			for k, c := range now {
				if _, ok := open[k]; !ok {
					open[k] = &LoopInterval{Dst: dst, Routers: c, Start: t}
				}
			}
		}
		for _, li := range open {
			li.End = to
			out = append(out, *li)
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Start != out[b].Start {
			return out[a].Start < out[b].Start
		}
		return out[a].Dst.Less(out[b].Dst)
	})
	return out
}
