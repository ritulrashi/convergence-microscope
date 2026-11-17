// Package ksym resolves kernel addresses to function names using
// /proc/kallsyms (root sees real addresses). Drop locations are stored as
// names because raw addresses change with every boot (KASLR).
package ksym

import (
	"bufio"
	"io"
	"sort"
	"strconv"
	"strings"
)

type sym struct {
	addr uint64
	name string
}

// Table is a sorted kernel symbol table.
type Table struct{ syms []sym }

// Parse reads kallsyms text ("ffffffff81000000 T _text" per line). Only text
// symbols (t, T) are kept.
func Parse(r io.Reader) (*Table, error) {
	var syms []sym
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 3 || (f[1] != "t" && f[1] != "T") {
			continue
		}
		a, err := strconv.ParseUint(f[0], 16, 64)
		if err != nil || a == 0 {
			continue
		}
		syms = append(syms, sym{a, f[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(syms, func(i, j int) bool { return syms[i].addr < syms[j].addr })
	return &Table{syms}, nil
}

// Name returns the function containing addr, or "" if unknown.
func (t *Table) Name(addr uint64) string {
	if t == nil || len(t.syms) == 0 {
		return ""
	}
	i := sort.Search(len(t.syms), func(i int) bool { return t.syms[i].addr > addr })
	if i == 0 {
		return ""
	}
	return t.syms[i-1].name
}
