package rtnl

import (
	"net/netip"
	"slices"
	"sort"
)

// State holds one router's main-table IPv4 routes, nexthop objects and link
// names, and turns each message into the per-prefix changes it causes.
//
// A route's effective next-hop set comes from its nexthop object when it has
// one (FRR 8+ installs every route through nexthop objects), else from the
// route's inline next hops. A change to a nexthop object is therefore a route
// change for every prefix whose route uses it, directly or through a group.
type State struct {
	routes map[netip.Prefix]Route
	nhs    map[uint32]Nexthop
	links  map[uint32]string
}

// Change is one prefix whose effective next-hop set changed.
type Change struct {
	Prefix netip.Prefix
	Old    []string
	New    []string
}

func NewState() *State {
	return &State{routes: map[netip.Prefix]Route{}, nhs: map[uint32]Nexthop{}, links: map[uint32]string{}}
}

// Ifname returns the name of an interface index, or "if<N>" if unknown.
func (s *State) Ifname(i uint32) string {
	if n, ok := s.links[i]; ok {
		return n
	}
	return "if" + itoa(i)
}

func itoa(i uint32) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// Effective returns the sorted next-hop set of a prefix: "gw@ifname" for a
// gateway, "direct@ifname" for a connected route, "blackhole",
// "unreachable", "prohibit", or "unresolved-nh:<id>" if the route names a
// nexthop object the state has not seen. An absent route gives nil.
func (s *State) Effective(p netip.Prefix) []string {
	r, ok := s.routes[p]
	if !ok {
		return nil
	}
	var hops []Hop
	var unresolved []string
	if r.NhID != 0 {
		hops, unresolved = s.resolve(r.NhID, 0)
	} else {
		hops = r.Inline
	}
	set := map[string]bool{}
	for _, h := range hops {
		set[s.hopString(h)] = true
	}
	for _, u := range unresolved {
		set[u] = true
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *State) hopString(h Hop) string {
	if h.Kind != "" {
		return h.Kind
	}
	if h.Gateway.IsValid() {
		return h.Gateway.String() + "@" + s.Ifname(h.Oif)
	}
	return "direct@" + s.Ifname(h.Oif)
}

func (s *State) resolve(id uint32, depth int) ([]Hop, []string) {
	nh, ok := s.nhs[id]
	if !ok || depth > 4 {
		return nil, []string{"unresolved-nh:" + itoa(id)}
	}
	if len(nh.Group) == 0 {
		return []Hop{nh.Hop}, nil
	}
	var hops []Hop
	var bad []string
	for _, m := range nh.Group {
		h, u := s.resolve(m, depth+1)
		hops = append(hops, h...)
		bad = append(bad, u...)
	}
	return hops, bad
}

func (s *State) keep(r Route) bool {
	return r.Table == RT_TABLE_MAIN && r.Type != RTN_LOCAL && r.Type != RTN_BROADCAST
}

// usesNh reports whether prefix p's route depends on nexthop id.
func (s *State) usesNh(r Route, id uint32) bool {
	if r.NhID == 0 {
		return false
	}
	var walk func(x uint32, d int) bool
	walk = func(x uint32, d int) bool {
		if x == id {
			return true
		}
		nh, ok := s.nhs[x]
		if !ok || d > 4 {
			return false
		}
		for _, m := range nh.Group {
			if walk(m, d+1) {
				return true
			}
		}
		return false
	}
	return walk(r.NhID, 0)
}

func (s *State) snapshot(ps []netip.Prefix) map[netip.Prefix][]string {
	m := make(map[netip.Prefix][]string, len(ps))
	for _, p := range ps {
		m[p] = s.Effective(p)
	}
	return m
}

func (s *State) diff(before map[netip.Prefix][]string) []Change {
	var out []Change
	for p, old := range before {
		nw := s.Effective(p)
		if !slices.Equal(old, nw) {
			out = append(out, Change{p, old, nw})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Prefix.String() < out[j].Prefix.String() })
	return out
}

// ApplyRoute applies a route message and returns the change it caused.
func (s *State) ApplyRoute(r Route, del bool) []Change {
	if !s.keep(r) {
		return nil
	}
	before := s.snapshot([]netip.Prefix{r.Prefix})
	if del {
		delete(s.routes, r.Prefix)
	} else {
		s.routes[r.Prefix] = r
	}
	return s.diff(before)
}

func (s *State) affected(ids ...uint32) []netip.Prefix {
	var ps []netip.Prefix
	for p, r := range s.routes {
		for _, id := range ids {
			if s.usesNh(r, id) {
				ps = append(ps, p)
				break
			}
		}
	}
	return ps
}

// ApplyNexthop applies a nexthop message and returns the prefix changes it
// caused. Deleting a nexthop removes it from every group; routes left with no
// usable nexthop object are removed, as the kernel does.
func (s *State) ApplyNexthop(n Nexthop, del bool) []Change {
	before := s.snapshot(s.affected(n.ID))
	if !del {
		s.nhs[n.ID] = n
		return s.diff(before)
	}
	s.deleteNexthop(n.ID)
	return s.diff(before)
}

// deleteNexthop removes a nexthop object, drops it from every group, removes
// groups left empty, and removes routes whose nexthop object is gone.
func (s *State) deleteNexthop(id uint32) {
	gone := map[uint32]bool{id: true}
	delete(s.nhs, id)
	for changed := true; changed; {
		changed = false
		for id, g := range s.nhs {
			if len(g.Group) == 0 {
				continue
			}
			kept := g.Group[:0:0]
			for _, m := range g.Group {
				if !gone[m] {
					kept = append(kept, m)
				}
			}
			if len(kept) != len(g.Group) {
				if len(kept) == 0 {
					delete(s.nhs, id)
					gone[id] = true
					changed = true
				} else {
					g.Group = kept
					s.nhs[id] = g
				}
			}
		}
	}
	for p, r := range s.routes {
		if r.NhID != 0 && gone[r.NhID] {
			delete(s.routes, p)
		}
	}
}

// ApplyLink records an interface name and applies the FIB changes the kernel
// makes on its own when a link goes down, which it does not announce over
// netlink (calibrated in results/calibration/recorder.jsonl):
//
//   - admin down or carrier loss: every nexthop object on the device is
//     deleted (nexthop_flush_dev), with the same group and route cascade as
//     RTM_DELNEXTHOP;
//   - admin down only: inline next hops on the device die, and a route with
//     no live inline next hop left is removed (fib_sync_down_dev). On carrier
//     loss inline next hops stay usable (ignore_routes_with_linkdown=0).
func (s *State) ApplyLink(l Link, del bool) []Change {
	if del {
		delete(s.links, l.Index)
		return nil
	}
	if l.Name != "" {
		s.links[l.Index] = l.Name
	}
	if !l.AdminDown() && !l.CarrierDown() {
		return nil
	}
	before := s.snapshot(s.Prefixes())
	for id, nh := range s.nhs {
		if len(nh.Group) == 0 && nh.Hop.Oif == l.Index && nh.Hop.Kind == "" {
			s.deleteNexthop(id)
		}
	}
	if l.AdminDown() {
		for p, r := range s.routes {
			if r.NhID != 0 || len(r.Inline) == 0 {
				continue
			}
			live := r.Inline[:0:0]
			for _, h := range r.Inline {
				if h.Kind != "" || h.Oif != l.Index {
					live = append(live, h)
				}
			}
			if len(live) == 0 {
				delete(s.routes, p)
			} else if len(live) != len(r.Inline) {
				r.Inline = live
				s.routes[p] = r
			}
		}
	}
	return s.diff(before)
}

// Prefixes returns every prefix in the table, sorted.
func (s *State) Prefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(s.routes))
	for p := range s.routes {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
