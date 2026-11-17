// Package replay rebuilds each router's forwarding state over time from the
// recorder's events and predicts, for every probe packet, what the network
// should have done with it.
//
// Forwarding state is F(router, destination, t): the next-hop set of the
// longest matching prefix whose route exists at time t. Next hops are the
// recorder's strings ("10.1.0.1@eth1", "direct@eth3", "blackhole", ...).
package replay

import (
	"net/netip"
	"sort"
)

// Change is one entry of a prefix's timeline: from T on, the set is Set
// (nil or empty: no route).
type Change struct {
	T   int64
	Set []string
}

// FIB holds every router's per-prefix timelines.
type FIB struct {
	routers map[string]map[netip.Prefix][]Change
}

func NewFIB() *FIB { return &FIB{routers: map[string]map[netip.Prefix][]Change{}} }

// Add appends a change. Changes for one (router, prefix) must be added in
// time order; Sort fixes the order if they were not.
func (f *FIB) Add(router string, p netip.Prefix, t int64, set []string) {
	m := f.routers[router]
	if m == nil {
		m = map[netip.Prefix][]Change{}
		f.routers[router] = m
	}
	m[p] = append(m[p], Change{t, set})
}

// Sort orders every timeline by time (stable, so same-time changes keep
// their input order and the last one wins).
func (f *FIB) Sort() {
	for _, m := range f.routers {
		for p, cs := range m {
			sort.SliceStable(cs, func(i, j int) bool { return cs[i].T < cs[j].T })
			m[p] = cs
		}
	}
}

// Routers returns the router names, sorted.
func (f *FIB) Routers() []string {
	out := make([]string, 0, len(f.routers))
	for r := range f.routers {
		out = append(out, r)
	}
	sort.Strings(out)
	return out
}

func at(cs []Change, t int64) []string {
	// last change with T <= t
	i := sort.Search(len(cs), func(i int) bool { return cs[i].T > t })
	if i == 0 {
		return nil
	}
	return cs[i-1].Set
}

// Lookup returns the next-hop set for dst at router r at time t, and the
// matched prefix. An empty result means no route.
func (f *FIB) Lookup(r string, dst netip.Addr, t int64) ([]string, netip.Prefix) {
	var best netip.Prefix
	var set []string
	for p, cs := range f.routers[r] {
		if !p.Contains(dst) || (best.IsValid() && p.Bits() <= best.Bits()) {
			continue
		}
		if s := at(cs, t); len(s) > 0 {
			best, set = p, s
		}
	}
	return set, best
}

// ChangeTimes returns every distinct change time across all routers, sorted.
func (f *FIB) ChangeTimes() []int64 {
	seen := map[int64]bool{}
	var out []int64
	for _, m := range f.routers {
		for _, cs := range m {
			for _, c := range cs {
				if !seen[c.T] {
					seen[c.T] = true
					out = append(out, c.T)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
