package probe

import (
	"bytes"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	in := Probe{Src: 1, Dst: 4, Sport: 40002, Seq: 1<<40 + 7, SentNs: 123456789012345}
	buf := make([]byte, 64)
	b := in.Encode(buf)
	if len(b) != Size {
		t.Fatalf("len %d", len(b))
	}
	out, err := Decode(b)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("got %+v want %+v", out, in)
	}
	if out.Flow().String() != "1>4:40002" {
		t.Fatalf("flow %s", out.Flow())
	}
}

func TestFixedLayout(t *testing.T) {
	// The tracer matches these bytes; changing the layout must fail this test.
	b := Probe{Src: 2, Dst: 3, Sport: 0x1234, Seq: 5, SentNs: 6}.Encode(make([]byte, Size))
	want := []byte{0x43, 0x4d, 0x50, 0x52, 1, 2, 3, 0, 0x34, 0x12, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !bytes.Equal(b, want) {
		t.Fatalf("layout\n got %v\nwant %v", b, want)
	}
}

func TestDecodeRejects(t *testing.T) {
	good := Probe{Src: 1, Dst: 2}.Encode(make([]byte, Size))
	if _, err := Decode(good[:20]); err != ErrShort {
		t.Fatalf("short: %v", err)
	}
	bad := append([]byte(nil), good...)
	bad[0] ^= 0xff
	if _, err := Decode(bad); err == nil {
		t.Fatal("bad magic accepted")
	}
	bad = append([]byte(nil), good...)
	bad[4] = 9
	if _, err := Decode(bad); err == nil {
		t.Fatal("bad version accepted")
	}
}

func TestScheduleDeterministic(t *testing.T) {
	s := Schedule{StartNs: 1000, IntervalNs: 1_000_000, Ports: []uint16{40000, 40001, 40002, 40003}}
	if s.Due(3) != 3_001_000 || s.Port(5) != 40001 || s.Port(4) != 40000 {
		t.Fatal("schedule")
	}
}
