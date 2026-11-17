package replay

import (
	"net/netip"
	"reflect"
	"testing"
)

// Hand-built timelines with known answers (SPEC 8).
//
//	h1 - A - B - h2      A also links to C; C links to B.
//
// Addresses: A-B 10.1.0.0/31 (A .0, B .1), A-C 10.1.0.2/31 (A .2, C .3),
// C-B 10.1.0.4/31 (C .4, B .5), h2 10.10.2.10 behind B's eth3.

var (
	dst = netip.MustParseAddr("10.10.2.10")
	pfx = netip.MustParsePrefix("10.10.2.0/24")
)

func topo() *Topo {
	a := netip.MustParseAddr
	return &Topo{
		AddrNode: map[netip.Addr]string{
			a("10.1.0.0"): "A", a("10.1.0.1"): "B", a("10.1.0.2"): "A", a("10.1.0.3"): "C",
			a("10.1.0.4"): "C", a("10.1.0.5"): "B", a("10.10.2.10"): "h2", a("10.10.1.10"): "h1",
		},
		Hosts: map[string]Host{"h1": {a("10.10.1.10"), "A"}, "h2": {a("10.10.2.10"), "B"}},
	}
}

const (
	toB    = "10.1.0.1@eth1" // at A
	toC    = "10.1.0.3@eth2" // at A
	toA    = "10.1.0.0@eth1" // at B
	toH2   = "direct@eth3"   // at B
	cToB   = "10.1.0.5@eth2" // at C
	perHop = 1000            // 1 us
)

func steady() *FIB {
	f := NewFIB()
	f.Add("A", pfx, 0, []string{toB})
	f.Add("B", pfx, 0, []string{toH2})
	f.Add("C", pfx, 0, []string{cToB})
	return f
}

func pred(f *FIB, sendAt int64) Prediction {
	return Predict(f, topo(), "A", dst, 64, HopTimes{SendNs: sendAt, PerHopNs: perHop})
}

func TestDelivered(t *testing.T) {
	if p := pred(steady(), 10); p.Fate != Delivered {
		t.Fatalf("got %+v", p)
	}
}

func TestBlackhole(t *testing.T) {
	f := steady()
	f.Add("B", pfx, 100, nil) // B loses its route at t=100
	p := pred(f, 200)
	if p.Fate != Blackhole || !reflect.DeepEqual(p.BlackholeAt, []string{"B"}) {
		t.Fatalf("got %+v", p)
	}
	f.Add("A", pfx, 300, []string{"blackhole"})
	if p := pred(f, 400); p.Fate != Blackhole || !reflect.DeepEqual(p.BlackholeAt, []string{"A"}) {
		t.Fatalf("blackhole route: got %+v", p)
	}
}

func TestTwoRouterLoop(t *testing.T) {
	f := steady()
	f.Add("B", pfx, 100, []string{toA}) // A->B, B->A
	p := pred(f, 200)
	if p.Fate != Loop || len(p.LoopNodes) == 0 {
		t.Fatalf("got %+v", p)
	}
	loops := Loops(f, topo(), []netip.Addr{dst}, 0, 1000)
	want := []LoopInterval{{Dst: dst, Routers: []string{"A", "B"}, Start: 100, End: 1000}}
	if !reflect.DeepEqual(loops, want) {
		t.Fatalf("loops %+v", loops)
	}
}

func TestEcmpAmbiguity(t *testing.T) {
	f := steady()
	f.Add("A", pfx, 100, []string{toB, toC})
	f.Add("C", pfx, 100, nil) // the C branch blackholes, the B branch delivers
	p := pred(f, 200)
	if p.Fate != Ambiguous || p.Branches[Delivered] == 0 || p.Branches[Blackhole] == 0 {
		t.Fatalf("got %+v", p)
	}
	// Both branches deliver: not ambiguous.
	f.Add("C", pfx, 300, []string{cToB})
	if p := pred(f, 400); p.Fate != Delivered {
		t.Fatalf("got %+v", p)
	}
}

func TestMidPathRouteChange(t *testing.T) {
	// B loses its route at t=1500. Arrival at A = send+1us, at B = send+2us,
	// so F must be read at B's arrival time, not at send time.
	f := steady()
	f.Add("B", pfx, 1500, nil)
	if p := pred(f, -1000); p.Fate != Delivered { // B at 1000 < 1500
		t.Fatalf("before change: got %+v", p)
	}
	if p := pred(f, 0); p.Fate != Blackhole { // B at 2000 > 1500, though sent before
		t.Fatalf("after change at B's arrival: got %+v", p)
	}
	// Observed hop times override the estimate.
	ht := HopTimes{SendNs: 0, Observed: []int64{10, 1400}, PerHopNs: perHop}
	if p := Predict(f, topo(), "A", dst, 64, ht); p.Fate != Delivered {
		t.Fatalf("observed times: got %+v", p)
	}
}

func TestShortLoopIsSurvived(t *testing.T) {
	// A loop that lasts 10 hop-times: a packet entering it escapes with TTL
	// to spare and is delivered.
	f := steady()
	f.Add("B", pfx, 0, []string{toA})
	f.Add("B", pfx, 10*perHop, []string{toH2})
	if p := pred(f, 0); p.Fate != Delivered {
		t.Fatalf("got %+v", p)
	}
	// A long one exhausts TTL.
	g := steady()
	g.Add("B", pfx, 0, []string{toA})
	g.Add("B", pfx, 1000*perHop, []string{toH2})
	if p := pred(g, 0); p.Fate != Loop {
		t.Fatalf("got %+v", p)
	}
}

func TestLongestPrefixWithMissingRoute(t *testing.T) {
	f := steady()
	host := netip.MustParsePrefix("10.10.2.10/32")
	f.Add("A", host, 0, []string{toC}) // more specific wins
	f.Add("A", host, 100, nil)         // removed: fall back to the /24
	if s, p := f.Lookup("A", dst, 50); p != host || !reflect.DeepEqual(s, []string{toC}) {
		t.Fatalf("got %v %v", s, p)
	}
	if s, p := f.Lookup("A", dst, 150); p != pfx || !reflect.DeepEqual(s, []string{toB}) {
		t.Fatalf("got %v %v", s, p)
	}
}

func TestAllowed(t *testing.T) {
	f := steady()
	if !Allowed(f, topo(), "A", "B", dst, 5) || Allowed(f, topo(), "A", "C", dst, 5) {
		t.Fatal("allowed")
	}
	if !Allowed(f, topo(), "B", "h2", dst, 5) {
		t.Fatal("delivery hop")
	}
}
