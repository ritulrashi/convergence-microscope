package ksym

import (
	"strings"
	"testing"
)

const sample = `ffffffff81000000 T _text
ffffffff81a00100 t ip_forward
ffffffff81a00500 T ip_error
ffffffff81a00900 d some_data
ffffffff81b00000 T dst_discard_out
0000000000000000 T zero_hidden
`

func TestName(t *testing.T) {
	tb, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[uint64]string{
		0xffffffff81a00100: "ip_forward",
		0xffffffff81a0017f: "ip_forward",
		0xffffffff81a00600: "ip_error",
		0xffffffff81a00950: "ip_error", // data symbols are skipped
		0xffffffff81b00010: "dst_discard_out",
		0x1000:             "",
	}
	for a, want := range cases {
		if got := tb.Name(a); got != want {
			t.Errorf("%#x: got %q want %q", a, got, want)
		}
	}
}
