package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/ritulrashi/convergence-microscope/go/internal/rtnl"
)

// TestReplayCalibration feeds the raw netlink captured during calibration
// (results/calibration/recorder/*.raw, copied to testdata/) back through the
// recorder logic and checks it reproduces, record for record, the FIB events
// the recorder wrote live.
func TestReplayCalibration(t *testing.T) {
	raws, _ := filepath.Glob("testdata/*.raw")
	if len(raws) == 0 {
		t.Skip("no testdata/*.raw fixtures")
	}
	for _, raw := range raws {
		t.Run(filepath.Base(raw), func(t *testing.T) {
			got := replay(t, raw)
			want := fibRecords(t, strings.TrimSuffix(raw, ".raw")+".jsonl")
			if len(want) == 0 {
				t.Fatal("fixture has no fib records")
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("replay differs from live output\n got %d records: %v\nwant %d records: %v", len(got), got, len(want), want)
			}
		})
	}
}

type fibRec struct {
	T        int64
	Prefix   string
	Old, New string
	Via, Msg string
}

func fibRecords(t *testing.T, path string) []fibRec {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []fibRec
	for _, line := range bytes.Split(b, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var r struct {
			Kind, Prefix, Via, Msg string
			T                      int64
			Old, New               []string
		}
		if err := json.Unmarshal(line, &r); err != nil {
			t.Fatal(err)
		}
		if r.Kind != "fib" {
			continue
		}
		out = append(out, fibRec{r.T, r.Prefix, strings.Join(r.Old, ","), strings.Join(r.New, ","), r.Via, r.Msg})
	}
	return out
}

func replay(t *testing.T, path string) []fibRec {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var buf bytes.Buffer
	o := &out{w: bufio.NewWriter(&buf), router: "replay"}
	discard := &out{w: bufio.NewWriter(nopWriter{})}
	st := rtnl.NewState()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4<<20), 4<<20)
	for sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) != 3 {
			t.Fatalf("bad raw line %q", sc.Text())
		}
		ts, _ := strconv.ParseInt(parts[0], 10, 64)
		b, err := hex.DecodeString(parts[2])
		if err != nil {
			t.Fatal(err)
		}
		ms, err := rtnl.Split(b)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			if parts[1] == "dump" {
				_, err = apply(st, discard, 0, "dump", m)
			} else {
				_, err = apply(st, o, ts, "event", m)
			}
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	o.w.Flush()
	tmp := filepath.Join(t.TempDir(), "out.jsonl")
	os.WriteFile(tmp, buf.Bytes(), 0o644)
	return fibRecords(t, tmp)
}
